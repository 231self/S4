## Maskura TypeScript SDK (`maskura-client`)

This generated TypeScript/JavaScript client uses the Fetch API. It is not
currently published to npm.

### Install From A Release

Download and extract the canonical SDK archive, then install the extracted
package directory:

```sh
curl -fLO https://github.com/231self/S4/releases/latest/download/maskura-typescript-sdk.tar.gz
mkdir -p vendor/maskura-client
tar -xzf maskura-typescript-sdk.tar.gz -C vendor/maskura-client
npm install --install-links ./vendor/maskura-client --save
```

The legacy `s4-typescript-sdk.tar.gz` release archive remains available with
`s4-client` package metadata. Both archives contain the same client API.

### Install From Source

From a checkout of `https://github.com/231self/S4`:

```sh
npm install --prefix sdks/typescript --no-package-lock
npm run --prefix sdks/typescript build
npm install --install-links ./sdks/typescript --save
```

### Build And Test

```sh
npm install
npm run build
node --test test/highlevel-attach.test.cjs
```

### Usage

```typescript
import { MaskuraClient } from "maskura-client";

const client = new MaskuraClient({
  endpoint: "https://api.s4.231self.com",
  accessKey: "s4_example",
  secretKey: "s4s_example",
});
```
