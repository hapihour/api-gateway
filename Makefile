deploy-dev:
	./scripts/build.sh
	serverless deploy --stage=dev
