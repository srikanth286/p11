up:
	docker compose -f docker-compose.yml up --build --force-recreate --no-deps -d softhsm
down:
	docker compose -f docker-compose.yml down
wipe:
	docker compose -f docker-compose.yml down -v
