package main

import (
	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/app"
)

func main() {
	app.Start()

	// TODO:
	// 1. update model: use user_uuid instead user_id
	// 2. add sharding based on user_uuid
	// 3. add to AuthRequired() setting user_uuid instead of user_id in utils module
}
