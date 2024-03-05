import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { DigestAlgorithmIdentifier } from "@peculiar/asn1-cms";
/**
 * DataGroupHash ::= SEQUENCE {
 *  dataGroupNumber DataGroupNumber,
 *  dataGroupHashValue OCTET STRING }
 */
export class DataGroupHash {
  @AsnProp({ type: AsnPropTypes.Integer })
  public dataGroupNumber: DataGroupNumber = DataGroupNumber.dataGroup1;

  @AsnProp({ type: AsnPropTypes.OctetString })
  public dataGroupHashValue: ArrayBuffer = new ArrayBuffer(0);

  public constructor(params: Partial<DataGroupHash> = {}) {
    Object.assign(this, params);
  }
}

/**
 * LDSSecurityObject ::= SEQUENCE {
 * version LDSSecurityObjectVersion,
 * hashAlgorithm DigestAlgorithmIdentifier,
 * dataGroupHashValues SEQUENCE SIZE (2..ub-DataGroups) OF
 * DataGroupHash}
 */
export class LDSSecurityObject {
    @AsnProp({ type: AsnPropTypes.Integer })
    public version: LDSSecurityObjectVersion = LDSSecurityObjectVersion.v1;
  
    @AsnProp({ type: DigestAlgorithmIdentifier })
    public hashAlgorithm: DigestAlgorithmIdentifier = new DigestAlgorithmIdentifier()
  
    @AsnProp({ type: DataGroupHash, repeated: "sequence" })
    public dataGroupHashValues: DataGroupHash[] = [];
  
    public constructor(params: Partial<LDSSecurityObject> = {}) {
      Object.assign(this, params);
    }
}

export enum LDSSecurityObjectVersion {
    v0 = 0,
    v1 = 1,
}

export enum DataGroupNumber {
    dataGroup1 = 1,
    dataGroup2 = 2,
    dataGroup3 = 3,
    dataGroup4 = 4,
    dataGroup5 = 5,
    dataGroup6 = 6,
    dataGroup7 = 7,
    dataGroup8 = 8,
    dataGroup9 = 9,
    dataGroup10 = 10,    
    dataGroup11 = 11,
    dataGroup12 = 12,
    dataGroup13 = 13,
    dataGroup14 = 14,
    dataGroup15 = 15,
    dataGroup16 = 16,
}
