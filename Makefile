start:
	RUST_LOG=debug cargo run
migrateup:
	sqlx migrate run
migratedown:
	sqlx migrate revert