# Changelog

## 0.1.0 (2026-11-27)


### Features

* add polytunnel and polytunnel-daemon binaries with --author ([edf404e](https://github.com/viru185/Polytunnel/commit/edf404e81034ebe007a54d473c4c6a0d38ecaf6f))
* add the embedded login window and the kill switch (M10, M11) ([#12](https://github.com/viru185/Polytunnel/issues/12)) ([d35e397](https://github.com/viru185/Polytunnel/commit/d35e397b9c0512359daffde8f13b6c155c262bb0))
* **app:** add the window and the tray agent (M6) ([#8](https://github.com/viru185/Polytunnel/issues/8)) ([fc1c1ed](https://github.com/viru185/Polytunnel/commit/fc1c1ed86fede7268acbedc45f30ba6ee750db4a))
* **daemon:** add the background service and the GlobalProtect tunnel (M4) ([#6](https://github.com/viru185/Polytunnel/issues/6)) ([128fed7](https://github.com/viru185/Polytunnel/commit/128fed7a794c532a070e213bf02e4c93d971957d))
* **forti:** add the Fortinet SSL VPN tunnel (M5) ([#7](https://github.com/viru185/Polytunnel/issues/7)) ([ab0ef27](https://github.com/viru185/Polytunnel/commit/ab0ef273c29e347e58315297d45e38c1b11be57d))
* **gp:** find GlobalProtect gateways and pick the best one (M2) ([#4](https://github.com/viru185/Polytunnel/issues/4)) ([51671d8](https://github.com/viru185/Polytunnel/commit/51671d8144c4c1b73004df80e7b5fd5f6f391db4))
* **ike:** add Fortinet IPsec over IKEv1 (M8) ([#10](https://github.com/viru185/Polytunnel/issues/10)) ([2b376e3](https://github.com/viru185/Polytunnel/commit/2b376e3dac974a656821cdc394caabd61e90fb49))
* **ike:** add IKEv2 with EAP, certificates and IPsec over TCP (M9) ([#11](https://github.com/viru185/Polytunnel/issues/11)) ([c9e800f](https://github.com/viru185/Polytunnel/commit/c9e800f6af91ac6455404d7bbc1fac1bc6fcac3a))
* log in to GlobalProtect and Fortinet from the command line (M1) ([#2](https://github.com/viru185/Polytunnel/issues/2)) ([f0fbda2](https://github.com/viru185/Polytunnel/commit/f0fbda232998f7fdebaa74034ee2b805f0d094ad))
* **net:** add network setup and ESP (M3) ([#5](https://github.com/viru185/Polytunnel/issues/5)) ([37c2db1](https://github.com/viru185/Polytunnel/commit/37c2db1d0f0f7b28f1b5b201dca05e4643ff398e))
* sign releases and install signed updates (M12, M13) ([#13](https://github.com/viru185/Polytunnel/issues/13)) ([8ec55dd](https://github.com/viru185/Polytunnel/commit/8ec55dd17ebd9d822c5a73cc3bb973435db776f4))


### Bug Fixes

* **net:** treat routes on a removed interface as already undone ([#14](https://github.com/viru185/Polytunnel/issues/14)) ([284c6c4](https://github.com/viru185/Polytunnel/commit/284c6c427d68f02db8602021386ea87bf07a60be))


### Documentation

* add README, contributing guide, security policy and architecture records ([3bc312d](https://github.com/viru185/Polytunnel/commit/3bc312ddae998daef1e91fe882adad9f835fa95e))
