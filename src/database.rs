use async_trait::async_trait;
use hbb_common::{log, ResultType};
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChangePeerIdOutcome {
    Changed,
    IdExists,
    IdentityMismatch,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = crate::common::get_arg_or("MAX_DATABASE_CONNECTIONS", "1".to_owned())
            .parse()
            .unwrap_or(1);
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query!(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);
        "
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query!(
            "insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
            guid,
            id,
            uuid,
            pk,
            info
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query!(
            "update peer set id=?, pk=?, info=? where guid=?",
            id,
            pk,
            info,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub(crate) async fn change_peer_id(
        &self,
        guid: &[u8],
        old_id: &str,
        new_id: &str,
        uuid: &[u8],
        pk: &[u8],
    ) -> ResultType<ChangePeerIdOutcome> {
        let result = sqlx::query(
            "update peer set id=? where guid=? and id=? and uuid=? and pk=?",
        )
        .bind(new_id)
        .bind(guid)
        .bind(old_id)
        .bind(uuid)
        .bind(pk)
        .execute(self.pool.get().await?.deref_mut())
        .await;

        match result {
            Ok(result) if result.rows_affected() == 1 => Ok(ChangePeerIdOutcome::Changed),
            Ok(_) => Ok(ChangePeerIdOutcome::IdentityMismatch),
            Err(err)
                if err
                    .as_database_error()
                    .and_then(|database_error| database_error.code())
                    .map(|code| code == "2067" || code == "1555")
                    .unwrap_or(false) =>
            {
                Ok(ChangePeerIdOutcome::IdExists)
            }
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ChangePeerIdOutcome;
    use hbb_common::tokio;
    #[test]
    fn test_insert() {
        insert();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn insert() {
        let db = super::Database::new("test.sqlite3").await.unwrap();
        let mut jobs = vec![];
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned
                    .insert_peer(&id, &empty_vec, &empty_vec, "")
                    .await
                    .unwrap();
            });
            jobs.push(a);
        }
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                cloned.get_peer(&id).await.unwrap();
            });
            jobs.push(a);
        }
        hbb_common::futures::future::join_all(jobs).await;
    }

    #[test]
    fn change_peer_id_is_atomic_and_identity_bound() {
        change_peer_id();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn change_peer_id() {
        let database_path = std::env::temp_dir().join(format!(
            "ongrow-rustdesk-server-change-id-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let database_path_string = database_path.to_string_lossy().to_string();
        let db = super::Database::new(&database_path_string).await.unwrap();
        let uuid_a = b"uuid-a";
        let public_key_a = b"public-key-a";
        let guid_a = db
            .insert_peer("123456789", uuid_a, public_key_a, "{}")
            .await
            .unwrap();
        db.insert_peer("OG-0002", b"uuid-b", b"public-key-b", "{}")
            .await
            .unwrap();

        assert_eq!(
            db.change_peer_id(
                &guid_a,
                "123456789",
                "OG-0001",
                uuid_a,
                public_key_a,
            )
            .await
            .unwrap(),
            ChangePeerIdOutcome::Changed,
        );
        assert!(db.get_peer("123456789").await.unwrap().is_none());
        assert!(db.get_peer("OG-0001").await.unwrap().is_some());

        assert_eq!(
            db.change_peer_id(
                &guid_a,
                "OG-0001",
                "OG-0002",
                uuid_a,
                public_key_a,
            )
            .await
            .unwrap(),
            ChangePeerIdOutcome::IdExists,
        );
        assert_eq!(
            db.change_peer_id(
                &guid_a,
                "OG-0001",
                "OG-0003",
                b"wrong-uuid",
                public_key_a,
            )
            .await
            .unwrap(),
            ChangePeerIdOutcome::IdentityMismatch,
        );

        drop(db);
        std::fs::remove_file(database_path).unwrap();
    }
}
