FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:3141bcd57286f8ca83fc1eb141d547ebbb5addf72ddc91ab512284dc4c163e33

COPY . /src/aiir
WORKDIR /src/aiir

COPY .clusterfuzzlite/build.sh /src/build.sh
