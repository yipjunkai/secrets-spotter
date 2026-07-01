# Changelog

## [1.3.0](https://github.com/yipjunkai/secrets-spotter/compare/v1.2.0...v1.3.0) (2026-07-01)


### Features

* **core:** filter published example keys and template placeholders ([#44](https://github.com/yipjunkai/secrets-spotter/issues/44)) ([91b5e74](https://github.com/yipjunkai/secrets-spotter/commit/91b5e7404f577572aa2cc7e17b68f2b8ac4f1885))
* **extension:** scan external JS bundles from the service worker ([#48](https://github.com/yipjunkai/secrets-spotter/issues/48)) ([76af730](https://github.com/yipjunkai/secrets-spotter/commit/76af730113fec39a877c2a6ca13ec841c50b37f6))
* **extension:** scan localStorage/sessionStorage and the URL ([#47](https://github.com/yipjunkai/secrets-spotter/issues/47)) ([9e664a6](https://github.com/yipjunkai/secrets-spotter/commit/9e664a69aefcb4fcf5ef588d68ff48079732d822))


### Documentation

* audit and refresh repo Markdown (README, CONTRIBUTING, SECURITY, fuzz) ([#49](https://github.com/yipjunkai/secrets-spotter/issues/49)) ([b9b7ccb](https://github.com/yipjunkai/secrets-spotter/commit/b9b7ccbe99d44bcc883b5f50deb998e39df3d971))

## [1.2.0](https://github.com/yipjunkai/secrets-spotter/compare/v1.1.0...v1.2.0) (2026-06-14)


### Features

* harden CLI, extension, and CI/release ([#7](https://github.com/yipjunkai/secrets-spotter/issues/7)) ([0013df9](https://github.com/yipjunkai/secrets-spotter/commit/0013df9023dff677a49b18278caaf62d1d2676e9))
* harden detection patterns and add legacy/current token formats ([#5](https://github.com/yipjunkai/secrets-spotter/issues/5)) ([5e27774](https://github.com/yipjunkai/secrets-spotter/commit/5e27774bc8bbfb5bead5568fde43c88848377d5a))


### Bug Fixes

* build-failure masking, CLI --max-size false negative, and dropped boot-time traffic ([#6](https://github.com/yipjunkai/secrets-spotter/issues/6)) ([6f6644e](https://github.com/yipjunkai/secrets-spotter/commit/6f6644e9a91a302f3c1a8be3bdc8fd65ca09cedc))
* entropy-gate the generic tier, widen plain-words, scale redact ([#36](https://github.com/yipjunkai/secrets-spotter/issues/36)) ([cc1a343](https://github.com/yipjunkai/secrets-spotter/commit/cc1a3436f770a95847d99d3ceb47cb24f6d9aaff))
* **extension:** close interceptor capture and filtering gaps ([#32](https://github.com/yipjunkai/secrets-spotter/issues/32)) ([847d6e8](https://github.com/yipjunkai/secrets-spotter/commit/847d6e8c4f655feda83dbb5832ec86ad1079b776))
* **extension:** nonce-gate the page-&gt;extension relay protocol ([#37](https://github.com/yipjunkai/secrets-spotter/issues/37)) ([db64755](https://github.com/yipjunkai/secrets-spotter/commit/db647556acac6053f84d18217e18f0996529a0a3))
* **extension:** service-worker and manifest hygiene ([#38](https://github.com/yipjunkai/secrets-spotter/issues/38)) ([0733a6b](https://github.com/yipjunkai/secrets-spotter/commit/0733a6be80e1796409e33bdca1f3eeacec4fa90c))
* preserve tab findings when merge input fails to deserialize ([#16](https://github.com/yipjunkai/secrets-spotter/issues/16)) ([088f62f](https://github.com/yipjunkai/secrets-spotter/commit/088f62fdf16ec2b37b0e9d77935ea1291c487c05))
* scan source maps and first-party /cdn paths ([#15](https://github.com/yipjunkai/secrets-spotter/issues/15)) ([c54c4b8](https://github.com/yipjunkai/secrets-spotter/commit/c54c4b80b34101b1f54060afdc6b3c2c6535a7a9))


### Performance

* ASCII-only regex shrinks wasm 31%, drop dead prefix filter, size gate ([#33](https://github.com/yipjunkai/secrets-spotter/issues/33)) ([705c25a](https://github.com/yipjunkai/secrets-spotter/commit/705c25a9c3d31a0f09b606bb0f146011861056fc))
* **cli:** speed profile, honest line numbers, oversized-skip notice ([#39](https://github.com/yipjunkai/secrets-spotter/issues/39)) ([4eaf5d9](https://github.com/yipjunkai/secrets-spotter/commit/4eaf5d9bd8ecb0762f509e4aadc3d99b9acab457))
* **extension:** stream-cap responses and bound DOM capture ([#35](https://github.com/yipjunkai/secrets-spotter/issues/35)) ([e3951ad](https://github.com/yipjunkai/secrets-spotter/commit/e3951ad84aba12daa2a29d31ee59fd2d1a7df552))
* restore scan benchmark with CI regression gate ([#14](https://github.com/yipjunkai/secrets-spotter/issues/14)) ([969cbc2](https://github.com/yipjunkai/secrets-spotter/commit/969cbc2e109a95455f29ce9aca174c7de3f2594e))
