Gitleaks runs straight from the upstream image `zricethezav/gitleaks` (MIT); no custom build needed.

Pinned by digest in `core/adapters/gitleaks.py` (`zricethezav/gitleaks:v8.21.0@sha256:5a6d3338fe0e85fb63c079e0880dc10ee0bc6be54b75a2cf089964fbba7e9bd6`), so the tag being moved upstream
cannot change what runs. To update: `docker buildx imagetools inspect zricethezav/gitleaks:<tag>`
and use the index `Digest:` line, here and in `action/build-images.sh`.
