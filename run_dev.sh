#!/bin/bash
set -e
cd "$(dirname "$0")"

COMPOSE="docker compose"

case "${1:-up}" in
  up)
    $COMPOSE up -d --build
    ;;
  down)
    $COMPOSE down
    ;;
  restart)
    $COMPOSE down
    $COMPOSE up -d --build
    ;;
  logs)
    $COMPOSE logs -f oauth2-server
    ;;
  *)
    echo "Uso: $0 [up|down|restart|logs]"
    exit 1
    ;;
esac
