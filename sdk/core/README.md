# @selfxyz/core

SDK for verifying passport proofs from Self.

## Installation

You can install with this command:

```bash
npm install @selfxyz/core
# or
yarn add @selfxyz/core
```

## Initialization

Initialize the verifier with your scope, endpoint, and configuration:

```typescript
import { SelfBackendVerifier } from '@selfxyz/core';

const selfBackendVerifier = new SelfBackendVerifier(
  scope, // Your application's unique scope
  endpoint, // Your verification endpoint URL
  mockPassport, // Whether to use testnet (true) or mainnet (false)
  allowedIds, // Map of allowed attestation IDs
  configStorage, // Configuration storage implementation
  userIdentifierType, // Type of user identifier ('hex' or 'uuid')
  maxProofAgeSeconds // Optional. How old a proof may be and still verify. Defaults to 86400
);
```

### Proof age

Every proof carries the date it was generated. By default `verify()` rejects a proof once that date is more than one day in the past, which suits a live verification flow. Pass `maxProofAgeSeconds` to accept older proofs, for example a stored proof that is re-verified later:

```typescript
new SelfBackendVerifier(
  scope,
  endpoint,
  false,
  allowedIds,
  configStorage,
  'uuid',
  90 * 24 * 60 * 60
);
```

The circuit only records a date, not a time, so the effective window is the value you pass plus up to 24 hours. The parameter widens the past bound only: a proof dated more than a day in the future is always rejected as clock skew.

## Configuration Storage

The SDK requires a configuration storage implementation. You can use the provided implementations:

```typescript
import { DefaultConfigStore, InMemoryConfigStore } from '@selfxyz/core';

// For simple use cases with a single config
const configStore = new DefaultConfigStore({
  minimumAge: 18,
  excludedCountries: ['IRN', 'PRK', 'RUS', 'SYR'],
  ofac: true,
});

// For dynamic config management
const configStore = new InMemoryConfigStore(async (userIdentifier, userDefinedData) => {
  // Return config ID based on user and data
  return 'config-id-' + userIdentifier;
});
```

## Verification

Verify a proof with the required parameters:

```typescript
const result = await selfBackendVerifier.verify(
  attestationId, // The attestation ID (e.g., 1 for passport)
  proof, // The cryptographic proof
  publicSignals, // Array of public signals from the proof
  userContextData // Hex string containing user context data
);
```

## Verification Result

The `verify` method returns a detailed verification result:

```typescript
export interface VerificationResult {
  attestationId: AttestationId;
  isValidDetails: {
    isValid: boolean; // Cryptographic validity of the proof
    isMinimumAgeValid: boolean; // Age verification result
    isOfacValid: boolean; // OFAC check results
  };
  forbiddenCountriesList: string[]; // List of forbidden countries from proof
  discloseOutput: GenericDiscloseOutput; // Revealed data from the passport
  userData: {
    userIdentifier: string; // User identifier
    userDefinedData: string; // User-defined data
  };
}
```

The `GenericDiscloseOutput` contains the revealed passport data:

```typescript
export type GenericDiscloseOutput = {
  nullifier: string; // Cryptographic nullifier to prevent reuse
  forbiddenCountriesListPacked: string[]; // Packed forbidden countries list
  issuingState: string; // Passport issuing country
  name: string; // User's name
  idNumber: string; // Passport number
  nationality: string; // User's nationality
  dateOfBirth: string; // Date of birth
  gender: string; // Gender
  expiryDate: string; // Passport expiry date
  minimumAge: string; // Age verification result
  ofac: boolean[]; // OFAC check results [passport_no, name_dob, name_yob]
};
```

## API Implementation Example

Here's an example of implementing an API endpoint that uses the SDK:

```typescript
import { NextApiRequest, NextApiResponse } from 'next';
import { SelfBackendVerifier, DefaultConfigStore } from '@selfxyz/core';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    try {
      const { attestationId, proof, publicSignals, userContextData } = req.body;

      if (!attestationId || !proof || !publicSignals || !userContextData) {
        return res.status(400).json({
          message: 'attestationId, proof, publicSignals, and userContextData are required',
        });
      }

      // Create configuration storage
      const configStore = new DefaultConfigStore({
        minimumAge: 18,
        excludedCountries: ['IRN', 'PRK', 'RUS', 'SYR'],
        ofac: true,
      });

      // Initialize the verifier
      const selfBackendVerifier = new SelfBackendVerifier(
        'my-application-scope',
        'https://my-api.com/api/verify',
        false, // Use mainnet
        new Map([[1, true]]), // Allow passport attestation
        configStore,
        'uuid' // User identifier type
      );

      // Verify the proof
      const result = await selfBackendVerifier.verify(
        attestationId,
        proof,
        publicSignals,
        userContextData
      );

      if (result.isValidDetails.isValid) {
        // Return successful verification response
        return res.status(200).json({
          status: 'success',
          result: true,
          userData: result.userData,
          discloseOutput: result.discloseOutput,
        });
      } else {
        // Return failed verification response
        return res.status(400).json({
          status: 'error',
          result: false,
          message: 'Verification failed',
          details: result.isValidDetails,
        });
      }
    } catch (error) {
      console.error('Error verifying proof:', error);
      return res.status(500).json({
        status: 'error',
        result: false,
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  } else {
    return res.status(405).json({ message: 'Method not allowed' });
  }
}
```

## Working with Country Codes

The SDK provides country code utilities for working with ISO 3-letter country codes:

```typescript
import { countries, countryCodes } from '@selfxyz/core';

// Examples of usage
const iranCode = countries.IRAN; // "IRN"
const northKoreaCode = countries.NORTH_KOREA; // "PRK"

// Get country name from code
const iranName = countryCodes.IRN; // "Iran (Islamic Republic of)"

// Use in configuration
const configStore = new DefaultConfigStore({
  excludedCountries: [countries.IRAN, countries.NORTH_KOREA, countries.SYRIA],
  ofac: true,
});
```

## Integration with SelfQRcode

This backend SDK is designed to work with the `@selfxyz/qrcode` package. When configuring your QR code, set the verification endpoint to point to your API that uses this SDK:

```typescript
import { SelfAppBuilder } from '@selfxyz/qrcode';

const selfApp = new SelfAppBuilder({
  appName: 'My Application',
  scope: 'my-application-scope',
  endpoint: 'https://my-api.com/api/verify', // Your API using SelfBackendVerifier
  logoBase64: myLogoBase64,
  userId,
  disclosures: {
    name: true,
    nationality: true,
    date_of_birth: true,
    passport_number: true,
    minimumAge: 20,
    excludedCountries: ['IRN', 'PRK'],
    ofac: true,
  },
}).build();
```

## Available Types and Exports

The SDK exports the following types and utilities:

```typescript
import {
  SelfBackendVerifier,
  DefaultConfigStore,
  InMemoryConfigStore,
  countries,
  countryCodes,
  AttestationId,
  VerificationResult,
  VerificationConfig,
  IConfigStorage,
} from '@selfxyz/core';
```

### Types

- `AttestationId`: Type for attestation identifiers (e.g., 1 for passport)
- `VerificationResult`: Result structure returned by the verifier
- `VerificationConfig`: Configuration for verification rules
- `IConfigStorage`: Interface for configuration storage implementations

### Utilities

- `countries`: Object mapping country names to 3-letter ISO codes
- `countryCodes`: Object mapping 3-letter ISO codes to full country names
- `DefaultConfigStore`: Simple configuration storage with a single config
- `InMemoryConfigStore`: In-memory configuration storage for dynamic configs

## Example

For a more advanced implementation example, see the [playground](https://github.com/selfxyz/playground/blob/main/pages/api/verify.ts).
