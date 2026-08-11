"""Dagger pipeline for S4: build, test, publish, deploy to Fly.io.

Run locally (requires the Dagger CLI + engine):
    dagger call ci
    dagger call publish --tag=main
    dagger call deploy --app=s4 --tag=main

In CI (Codeberg Forgejo Actions), the workflow injects envvars/secrets
(FLY_API_TOKEN, SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_JWT_SECRET,
DATABASE_URL, S4_SERVICE_BUCKETS, AUTH_DISABLED) and calls the same
functions. See .kilo/plans/ci-cd-flyio.md.
"""

import os

import dagger
from dagger import dag, function, object_type

REGISTRY = "ghcr.io/231self/s4"
DEFAULT_APP = "s4"

# Runtime envvars passed to Fly as secrets (never baked into the image).
DEPLOY_SECRETS = (
    "SUPABASE_URL",
    "SUPABASE_ANON_KEY",
    "SUPABASE_JWT_SECRET",
    "DATABASE_URL",
    "S4_SERVICE_BUCKETS",
    "AUTH_DISABLED",
    "S4_WASM_FUEL",
    "S4_FILTER_COMPONENT",
)


@object_type
class S4:
    @function
    async def builder(self) -> dagger.Container:
        """Rust builder: workspace + wasm32 target + wasm-tools."""
        src = (
            dag.host(directory=".")
            .without_directory("target")
            .without_directory("node_modules")
            .without_directory("sdks/typescript/node_modules")
        )
        return (
            dag.container()
            .from_("rust:1-bookworm")
            .with_directory("/src", src)
            .with_workdir("/src")
            .with_exec(["rustup", "target", "add", "wasm32-unknown-unknown"])
            .with_exec(
                ["cargo", "install", "--locked", "wasm-tools", "--version", "1.255.0"]
            )
        )

    @function
    async def ci(self) -> str:
        """Build filters + gateway, then fmt / clippy / test."""
        ctr = await self.builder()
        ctr = ctr.with_exec(["bash", "scripts/build-filters.sh"])
        ctr = ctr.with_exec(["cargo", "fmt", "--check"])
        ctr = ctr.with_exec(["cargo", "clippy", "--all-targets", "--", "-D", "warnings"])
        ctr = ctr.with_exec(["cargo", "test", "--workspace"])
        return await ctr.stdout()

    @function
    async def image(self) -> dagger.Container:
        """Assemble the deploy image: release binary + Wasm components + certs."""
        builder = await self.builder()
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
    async def publish(self, tag: str) -> str:
        """Build + publish the deploy image; returns the image reference."""
        img = await self.image()
        return await img.publish(f"{REGISTRY}:{tag}")

    @function
    async def deploy(self, app: str = DEFAULT_APP, tag: str = "latest") -> str:
        """Set Fly secrets from env and deploy the published image."""
        ref = await self.publish(tag)

        fly = (
            dag.container()
            .from_("ghcr.io/superfly/flyctl:latest")
            .with_env_variable("FLY_API_TOKEN", os.environ.get("FLY_API_TOKEN", ""))
            .with_env_variable("FLY_APP", app)
        )

        # Pass non-empty deploy envvars as Fly secrets.
        for name in DEPLOY_SECRETS:
            value = os.environ.get(name, "")
            if value:
                fly = fly.with_secret_variable(name, dag.set_secret(name, value))

        return await fly.with_exec(
            ["flyctl", "deploy", "--image", ref, "--app", app, "--detach"]
        ).stdout()
