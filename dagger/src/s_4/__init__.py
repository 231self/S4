"""Dagger pipeline for S4: build, test, publish.

Run locally (requires the Dagger CLI + engine):
    dagger call ci                      # fmt + clippy + filters + tests (cached)
    dagger call image                   # assemble the deploy image
    dagger call publish --tag=v0.2.0    # build + push ghcr.io/231self/s4/s4:<tag>

Sources are cloned in-engine via dag.git (no host filesystem dependency),
and cargo registry + target dirs live on persistent cache volumes, so
repeated runs reuse compiled dependencies instead of recompiling.
"""

import dagger
from dagger import dag, function, object_type

REGISTRY = "ghcr.io/231self/s4/s4"
REPO = "https://github.com/231self/S4.git"
DEFAULT_REF = "main"


@object_type
class S4:
    @function
    async def builder(self, ref: str = DEFAULT_REF) -> dagger.Container:
        """Rust builder: workspace + wasm32 target + wasm-tools, cargo-cached."""
        tree = dag.git(REPO).branch(ref).tree()
        return (
            dag.container()
            .from_("rust:1-bookworm")
            .with_directory("/src", tree)
            .with_workdir("/src")
            .with_env_variable("CARGO_HOME", "/cargo")
            .with_mounted_cache("/cargo", dag.cache_volume("s4-cargo-registry"))
            .with_mounted_cache("/src/target", dag.cache_volume("s4-cargo-target"))
            .with_exec(["rustup", "target", "add", "wasm32-unknown-unknown"])
            .with_exec(
                ["cargo", "install", "--locked", "wasm-tools", "--version", "1.255.0"]
            )
        )

    @function
    async def ci(self, ref: str = DEFAULT_REF) -> str:
        """Build filters + gateway, then fmt / clippy / test."""
        ctr = await self.builder(ref)
        ctr = ctr.with_exec(["bash", "scripts/build-filters.sh"])
        ctr = ctr.with_exec(["cargo", "fmt", "--check"])
        ctr = ctr.with_exec(["cargo", "clippy", "--all-targets", "--", "-D", "warnings"])
        ctr = ctr.with_exec(["cargo", "test", "--workspace"])
        return await ctr.stdout()

    @function
    async def image(self, ref: str = DEFAULT_REF) -> dagger.Container:
        """Assemble the deploy image: release binary + Wasm components + certs."""
        builder = await self.builder(ref)
        builder = builder.with_exec(["bash", "scripts/build-filters.sh"])
        builder = builder.with_exec(["cargo", "build", "--release", "-p", "s4-gateway"])

        return (
            dag.container()
            .from_("debian:bookworm-slim")
            .with_exec(["apt-get", "update"])
            .with_exec(
                ["apt-get", "install", "-y", "--no-install-recommends", "ca-certificates"]
            )
            .with_exec(["rm", "-rf", "/var/lib/apt/lists/*"])
            .with_file(
                "/usr/local/bin/s4-gateway",
                builder.file("/src/target/release/s4-gateway"),
            )
            .with_directory(
                "/app/components",
                builder.directory("/src/target/components"),
            )
            .with_env_variable(
                "S4_FILTER_COMPONENT", "/app/components/pii-default.component.wasm"
            )
            .with_env_variable("S4_PLUGINS_DIR", "/app/components")
            .with_env_variable("LISTEN_ADDR", "0.0.0.0:8080")
            .with_exposed_port(8080)
            .with_entrypoint(["s4-gateway"])
        )

    @function
    async def publish(self, tag: str, ref: str = DEFAULT_REF) -> str:
        """Build + publish the deploy image; returns the image reference."""
        img = await self.image(ref)
        return await img.publish(f"{REGISTRY}:{tag}")
