CONTAINER_ORG=colin-stubbs
CONTAINER_NAME=corelight
CONTAINER_TAG=latest

# remove any old containers
docker rmi --force "${CONTAINER_ORG}/${CONTAINER_NAME}"

# build the container
docker build --rm=true --force-rm=true --no-cache -t "${CONTAINER_ORG}/${CONTAINER_NAME}:${CONTAINER_TAG}" -f container/Dockerfile container
