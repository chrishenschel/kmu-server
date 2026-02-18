#!/bin/bash
docker compose -f docker-compose.yaml down 
rm .env
rm /synapse/data/*
rm -rf /stalwart/data/etc
rm -rf /stalwart/data/logs
rm -rf /stalwart/data/data
