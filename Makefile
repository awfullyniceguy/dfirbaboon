PROJECT_PREFIX ?= dfirbaboon
AWS_REGION     ?= $(shell aws configure get region 2>/dev/null || echo "us-east-1")
AWS_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --query Account --output text 2>/dev/null)
IMAGE_NAME     ?= $(PROJECT_PREFIX)-worker
IMAGE_TAG      ?= latest
ECR_REGISTRY   := $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ECR_REPO_URI   := $(ECR_REGISTRY)/$(IMAGE_NAME)
INTAKE_BUCKET  := $(PROJECT_PREFIX)-intake-$(AWS_ACCOUNT_ID)
PLATFORM       ?= linux/amd64

.PHONY: help init fmt validate test build push deploy test-drop destroy clean

help: ## Display available Makefile targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

init: ## Initialize Terraform providers and backend in terraform/
	terraform -chdir=terraform init

fmt: ## Format Terraform configuration files
	terraform -chdir=terraform fmt -recursive

validate: ## Validate Terraform configuration and Python syntax
	terraform -chdir=terraform validate
	python3 -m py_compile worker/config.py worker/entrypoint.py worker/parsers/*.py

test: ## Run unit test suite
	python3 -m unittest discover -s tests -v

build: ## Build the dfirbaboon-worker Docker container image
	docker build --platform $(PLATFORM) -t $(IMAGE_NAME):$(IMAGE_TAG) worker/

push: build ## Authenticate to AWS ECR, tag, and push the dfirbaboon-worker image
	@if [ -z "$(AWS_ACCOUNT_ID)" ]; then \
		echo "Error: Unable to resolve AWS_ACCOUNT_ID. Check your AWS credentials."; \
		exit 1; \
	fi
	aws ecr get-login-password --region $(AWS_REGION) | docker login --username AWS --password-stdin $(ECR_REGISTRY)
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(ECR_REPO_URI):$(IMAGE_TAG)
	docker push $(ECR_REPO_URI):$(IMAGE_TAG)

deploy: ## Provision the dfirbaboon serverless infrastructure with Terraform
	terraform -chdir=terraform apply \
		-var="project_prefix=$(PROJECT_PREFIX)" \
		-var="aws_region=$(AWS_REGION)" \
		-var="worker_image_tag=$(IMAGE_TAG)"

test-drop: ## Generate and upload a sample artifact to s3://dfirbaboon-intake-<account_id>/INC10001/test_disk.raw
	@if [ -z "$(AWS_ACCOUNT_ID)" ]; then \
		echo "Error: Unable to resolve AWS_ACCOUNT_ID. Check your AWS credentials."; \
		exit 1; \
	fi
	@echo "Creating synthetic test artifact /tmp/test_disk.raw..."
	@dd if=/dev/zero of=/tmp/test_disk.raw bs=1M count=4 status=none
	@printf "MZ-DFIRBABOON-TEST-SAMPLE powershell.exe -EncodedCommand SQBFAFgA vssadmin delete shadows\n" >> /tmp/test_disk.raw
	@echo "Uploading /tmp/test_disk.raw to s3://$(INTAKE_BUCKET)/INC10001/test_disk.raw..."
	aws s3 cp /tmp/test_disk.raw s3://$(INTAKE_BUCKET)/INC10001/test_disk.raw --region $(AWS_REGION)
	@rm -f /tmp/test_disk.raw
	@echo "Triggered! Monitor Fargate worker logs in CloudWatch Log Group: /ecs/$(PROJECT_PREFIX)-tsk-worker"
	@echo "Output vault bucket will be provisioned at: s3://$(PROJECT_PREFIX)-inc10001-$(AWS_ACCOUNT_ID)/"

destroy: ## Tear down Terraform-managed infrastructure
	terraform -chdir=terraform destroy \
		-var="project_prefix=$(PROJECT_PREFIX)" \
		-var="aws_region=$(AWS_REGION)"
