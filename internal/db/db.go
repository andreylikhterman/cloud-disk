package db

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var DB *sql.DB

func InitDB(connString string) error {
	var err error
	DB, err = sql.Open("pgx", connString)
	if err != nil {
		return err
	}

	for i := 0; i < 30; i++ {
		if err := DB.Ping(); err == nil {
			log.Println("Connected to database")
			return nil
		}
		log.Printf("Waiting for database... (%d/30)\n", i+1)
		time.Sleep(1 * time.Second)
	}

	return err
}
