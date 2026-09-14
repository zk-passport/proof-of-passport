import { ethers } from 'ethers';
import { hashEndpointWithScope } from '@selfxyz/common/utils/scope';
import {
  AadhaarVerifier,
  AadhaarVerifier__factory,
  IdentityVerificationHubImpl,
  IdentityVerificationHubImpl__factory,
  KycVerifier,
  KycVerifier__factory,
  Registry__factory,
  Verifier,
  Verifier__factory,
} from './typechain-types/index.js';
import { discloseIndices } from './utils/constants.js';
import { formatRevealedDataPacked } from './utils/id.js';
import { AttestationId, VcAndDiscloseProof, VerificationConfig } from './types/types.js';
import { Country3LetterCode } from '@selfxyz/common/constants/countries';
import { calculateUserIdentifierHash } from './utils/hash.js';
import { castToUserIdentifier, UserIdType } from '@selfxyz/common/utils/circuits/uuid';
import {
  ConfigMismatch,
  ConfigMismatchError,
  RegistryContractError,
  VerifierContractError,
} from './errors/index.js';
import { IConfigStorage } from './store/interface.js';
import { unpackForbiddenCountriesList } from './utils/utils.js';
import { checkCircuitTimestamp, DEFAULT_MAX_PROOF_AGE_SECONDS } from './utils/timestamp.js';
import { BigNumberish } from 'ethers';

const CELO_MAINNET_RPC_URL = 'https://forno.celo.org';
const CELO_TESTNET_RPC_URL = 'https://forno.celo-sepolia.celo-testnet.org';

const IDENTITY_VERIFICATION_HUB_ADDRESS = '0xe57F4773bd9c9d8b6Cd70431117d353298B9f5BF';
const IDENTITY_VERIFICATION_HUB_ADDRESS_STAGING = '0x16ECBA51e18a4a7e61fdC417f0d47AFEeDfbed74';

const DEPRECATION_WARNED_KEY = Symbol.for('selfxyz.core.deprecation-warned');

/**
 * @deprecated The open-source Self Pass SDK is legacy. New integrations must use
 * `SelfClient` from `@selfxyz/enterprise-sdk` — the managed verifier replaces this class.
 * Migration guide: https://docs.self.xyz/docs/self-enterprise/migration/from-self-pass-sdk/
 */
export class SelfBackendVerifier {
  protected scope: string;
  protected identityVerificationHubContract: IdentityVerificationHubImpl;
  protected configStorage: IConfigStorage;
  protected provider: ethers.JsonRpcProvider;
  protected allowedIds: Map<AttestationId, boolean>;
  protected userIdentifierType: UserIdType;
  protected maxProofAgeSeconds: number;

  /**
   * @param maxProofAgeSeconds How far in the past a proof's circuit date may lie and still
   * verify. Defaults to 86400 (one day), which is the historical behaviour. The circuit only
   * records a date, so the effective window is this value plus up to 24 hours. Only the past
   * bound is widened; a proof dated more than a day in the future is always rejected.
   */
  constructor(
    scope: string,
    endpoint: string,
    mockPassport: boolean = false,
    allowedIds: Map<AttestationId, boolean>,
    configStorage: IConfigStorage,
    userIdentifierType: UserIdType,
    maxProofAgeSeconds: number = DEFAULT_MAX_PROOF_AGE_SECONDS
  ) {
    if (!Number.isFinite(maxProofAgeSeconds) || maxProofAgeSeconds < 0) {
      throw new RangeError('maxProofAgeSeconds must be a finite, non-negative number');
    }
    if (!(globalThis as Record<symbol, unknown>)[DEPRECATION_WARNED_KEY]) {
      (globalThis as Record<symbol, unknown>)[DEPRECATION_WARNED_KEY] = true;
      console.warn(
        '[@selfxyz/core] SelfBackendVerifier is deprecated — new integrations must use @selfxyz/enterprise-sdk. Migration guide: https://docs.self.xyz/docs/self-enterprise/migration/from-self-pass-sdk/'
      );
    }
    const rpcUrl = mockPassport ? CELO_TESTNET_RPC_URL : CELO_MAINNET_RPC_URL;
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const identityVerificationHubAddress = mockPassport
      ? IDENTITY_VERIFICATION_HUB_ADDRESS_STAGING
      : IDENTITY_VERIFICATION_HUB_ADDRESS;
    this.identityVerificationHubContract = IdentityVerificationHubImpl__factory.connect(
      identityVerificationHubAddress,
      provider
    );
    this.provider = provider;
    this.scope = hashEndpointWithScope(endpoint, scope);
    this.allowedIds = allowedIds;
    this.configStorage = configStorage;
    this.userIdentifierType = userIdentifierType;
    this.maxProofAgeSeconds = maxProofAgeSeconds;
  }

  public async verify(
    attestationId: AttestationId,
    proof: VcAndDiscloseProof,
    pubSignals: BigNumberish[],
    userContextData: string
  ) {
    //check if attestation id is allowed
    const allowedId = this.allowedIds.get(attestationId);
    let issues: Array<{ type: ConfigMismatch; message: string }> = [];
    if (!allowedId) {
      issues.push({
        type: ConfigMismatch.InvalidId,
        message: 'Attestation ID is not allowed, received: ' + attestationId,
      });
    }

    const publicSignals = pubSignals
      .map(String)
      .map((x) => (/[a-f]/g.test(x) && x.length > 0 ? '0x' + x : x));
    //check if user context hash matches
    const userContextHashInCircuit = BigInt(
      publicSignals[discloseIndices[attestationId].userIdentifierIndex]
    );
    const userContextHash = BigInt(
      calculateUserIdentifierHash(Buffer.from(userContextData, 'hex'))
    );

    if (userContextHashInCircuit !== userContextHash) {
      issues.push({
        type: ConfigMismatch.InvalidUserContextHash,
        message:
          'User context hash does not match with the one in the circuit\nCircuit: ' +
          userContextHashInCircuit +
          '\nUser context hash: ' +
          userContextHash,
      });
    }

    //check if scope matches
    const isValidScope = this.scope === publicSignals[discloseIndices[attestationId].scopeIndex];
    if (!isValidScope) {
      issues.push({
        type: ConfigMismatch.InvalidScope,
        message:
          'Scope does not match with the one in the circuit\nCircuit: ' +
          publicSignals[discloseIndices[attestationId].scopeIndex] +
          '\nScope: ' +
          this.scope,
      });
    }

    //check the root
    try {
      const registryAddress = await this.identityVerificationHubContract.registry(
        '0x' + attestationId.toString(16).padStart(64, '0')
      );
      if (registryAddress === '0x0000000000000000000000000000000000000000') {
        throw new RegistryContractError('Registry contract not found');
      }
      const registryContract = Registry__factory.connect(registryAddress, this.provider);
      const currentRoot = await registryContract.checkIdentityCommitmentRoot(
        publicSignals[discloseIndices[attestationId].merkleRootIndex]
      );
      if (!currentRoot) {
        issues.push({
          type: ConfigMismatch.InvalidRoot,
          message:
            'Onchain root does not exist, received: ' +
            publicSignals[discloseIndices[attestationId].merkleRootIndex],
        });
      }
    } catch (error) {
      throw new RegistryContractError('Registry contract not found');
    }

    //check if attestation id matches
    const isValidAttestationId =
      attestationId.toString() === publicSignals[discloseIndices[attestationId].attestationIdIndex];
    if (!isValidAttestationId) {
      issues.push({
        type: ConfigMismatch.InvalidAttestationId,
        message: 'Attestation ID does not match with the one in the circuit',
      });
    }

    const userIdentifier = castToUserIdentifier(
      BigInt('0x' + userContextData.slice(64, 128)),
      this.userIdentifierType
    );
    const userDefinedData = userContextData.slice(128);
    const configId = await this.configStorage.getActionId(userIdentifier, userDefinedData);
    if (!configId) {
      issues.push({
        type: ConfigMismatch.ConfigNotFound,
        message: 'Config Id not found',
      });
    }

    let verificationConfig: VerificationConfig | null;
    try {
      verificationConfig = await this.configStorage.getConfig(configId);
    } catch (error) {
      issues.push({
        type: ConfigMismatch.ConfigNotFound,
        message: `Config not found for ${configId}`,
      });
    } finally {
      if (!verificationConfig) {
        issues.push({
          type: ConfigMismatch.ConfigNotFound,
          message: `Config not found for ${configId}`,
        });
        throw new ConfigMismatchError(issues);
      }
    }

    //check if forbidden countries list matches
    const forbiddenCountriesList: string[] = unpackForbiddenCountriesList(
      [0, 1, 2, 3].map(
        (x) => publicSignals[discloseIndices[attestationId].forbiddenCountriesListPackedIndex + x]
      )
    );
    const forbiddenCountriesListVerificationConfig = verificationConfig.excludedCountries || [];

    const isForbiddenCountryListValid = forbiddenCountriesListVerificationConfig.every((country) =>
      forbiddenCountriesList.includes(country as Country3LetterCode)
    );
    if (!isForbiddenCountryListValid) {
      issues.push({
        type: ConfigMismatch.InvalidForbiddenCountriesList,
        message:
          'Forbidden countries list in config does not match with the one in the circuit\nCircuit: ' +
          forbiddenCountriesList.join(', ') +
          '\nConfig: ' +
          forbiddenCountriesListVerificationConfig.join(', '),
      });
    }

    const genericDiscloseOutput = formatRevealedDataPacked(attestationId, publicSignals);
    //check if minimum age matches
    const isMinimumAgeValid =
      verificationConfig.minimumAge !== undefined
        ? verificationConfig.minimumAge === Number.parseInt(genericDiscloseOutput.minimumAge, 10) ||
          genericDiscloseOutput.minimumAge === '00'
        : true;
    if (!isMinimumAgeValid) {
      issues.push({
        type: ConfigMismatch.InvalidMinimumAge,
        message:
          'Minimum age in config does not match with the one in the circuit\nCircuit: ' +
          genericDiscloseOutput.minimumAge +
          '\nConfig: ' +
          verificationConfig.minimumAge,
      });
    }

    let circuitTimestampYy: number[];
    let circuitTimestampMm: number[];
    let circuitTimestampDd: number[];
    if (attestationId === 4) {
      circuitTimestampYy = publicSignals
        .slice(
          discloseIndices[attestationId].currentDateIndex,
          discloseIndices[attestationId].currentDateIndex + 4
        )
        .map(Number);
      circuitTimestampMm = publicSignals
        .slice(
          discloseIndices[attestationId].currentDateIndex + 4,
          discloseIndices[attestationId].currentDateIndex + 6
        )
        .map(Number);
      circuitTimestampDd = publicSignals
        .slice(
          discloseIndices[attestationId].currentDateIndex + 6,
          discloseIndices[attestationId].currentDateIndex + 8
        )
        .map(Number);
    } else if (attestationId === 3) {
      circuitTimestampYy = String(publicSignals[discloseIndices[attestationId].currentDateIndex])
        .split('')
        .map(Number);
      circuitTimestampMm = String(
        publicSignals[discloseIndices[attestationId].currentDateIndex + 1]
      )
        .split('')
        .map(Number);
      circuitTimestampDd = String(
        publicSignals[discloseIndices[attestationId].currentDateIndex + 2]
      )
        .split('')
        .map(Number);
    } else {
      circuitTimestampYy = [
        2,
        0,
        +publicSignals[discloseIndices[attestationId].currentDateIndex],
        +publicSignals[discloseIndices[attestationId].currentDateIndex + 1],
      ];
      circuitTimestampMm = [
        +publicSignals[discloseIndices[attestationId].currentDateIndex + 2],
        +publicSignals[discloseIndices[attestationId].currentDateIndex + 3],
      ];
      circuitTimestampDd = [
        +publicSignals[discloseIndices[attestationId].currentDateIndex + 4],
        +publicSignals[discloseIndices[attestationId].currentDateIndex + 5],
      ];
    }

    // the app stamps the circuit date in UTC, so read it back as UTC midnight
    const circuitTimestamp = new Date(
      Date.UTC(
        Number(circuitTimestampYy.join('')),
        Number(circuitTimestampMm.join('')) - 1,
        Number(circuitTimestampDd.join(''))
      )
    );
    issues.push(...checkCircuitTimestamp(circuitTimestamp, new Date(), this.maxProofAgeSeconds));

    if (issues.length > 0) {
      throw new ConfigMismatchError(issues);
    }

    let verifierContract: Verifier | AadhaarVerifier | KycVerifier;
    try {
      const verifierAddress = await this.identityVerificationHubContract.discloseVerifier(
        '0x' + attestationId.toString(16).padStart(64, '0')
      );
      if (verifierAddress === '0x0000000000000000000000000000000000000000') {
        throw new VerifierContractError('Verifier contract not found');
      }
      if (attestationId === 4) {
        verifierContract = KycVerifier__factory.connect(verifierAddress, this.provider);
      } else if (attestationId === 3) {
        verifierContract = AadhaarVerifier__factory.connect(verifierAddress, this.provider);
      } else {
        verifierContract = Verifier__factory.connect(verifierAddress, this.provider);
      }
    } catch (error) {
      throw new VerifierContractError('Verifier contract not found');
    }

    let isValid = false;
    try {
      isValid = await verifierContract.verifyProof(
        proof.a,
        [
          [proof.b[0][1], proof.b[0][0]],
          [proof.b[1][1], proof.b[1][0]],
        ],
        proof.c,
        publicSignals
      );
    } catch (error) {
      isValid = false;
    }

    const cumulativeOfac = genericDiscloseOutput.ofac.reduce((acc, curr) => acc || curr, false);

    return {
      attestationId,
      isValidDetails: {
        isValid,
        isMinimumAgeValid:
          verificationConfig.minimumAge !== undefined
            ? verificationConfig.minimumAge <= Number.parseInt(genericDiscloseOutput.minimumAge, 10)
            : true,
        isOfacValid:
          //isOfacValid is true when a person is in OFAC list
          verificationConfig.ofac !== undefined && verificationConfig.ofac ? cumulativeOfac : false,
      },
      forbiddenCountriesList,
      discloseOutput: genericDiscloseOutput,
      userData: {
        userIdentifier,
        userDefinedData,
      },
    };
  }
}
