import { assert, expect } from 'chai'
import path from "path";
import { formatMrz, hash, formatSigAlgNameForCircuit, bigIntToChunkedBytes, formatAndConcatenateDataHashes } from "../src/utils/utils";
import { mockPassportData_sha256WithRSAEncryption_65537 } from "../src/utils/mockPassportData";

describe("Common utils", function () {
    const mrz = "P<FRADUPONT<<ALPHONSE<HUGUES<ALBERT<<<<<<<<<" +
    "24HB818324FRA0402111M3111115<<<<<<<<<<<<<<02";

    it("should format mrz", async function () {

        const formatted = formatMrz(mrz);
        expect(formatted).to.deep.equal(
            [
                97, 91, 95, 31, 88, 80, 60, 70, 82, 65, 68, 85,
                80, 79, 78, 84, 60, 60, 65, 76, 80, 72, 79, 78,
                83, 69, 60, 72, 85, 71, 85, 69, 83, 60, 65, 76,
                66, 69, 82, 84, 60, 60, 60, 60, 60, 60, 60, 60,
                60, 50, 52, 72, 66, 56, 49, 56, 51, 50, 52, 70,
                82, 65, 48, 52, 48, 50, 49, 49, 49, 77, 51, 49,
                49, 49, 49, 49, 53, 60, 60, 60, 60, 60, 60, 60,
                60, 60, 60, 60, 60, 60, 60, 48, 50
              ]
            );
    });

    it("should format and concatenate data hashes", async function () {
        const signatureAlgorithm = 'sha256WithRSAEncryption';
        const mrzHash = hash(signatureAlgorithm, formatMrz(mrz));
        const offset = 31;
        const sampleDataHashes = [
            [
              2,
              [-66, 82, -76, -21, -34, 33, 79, 50, -104, -120, -114, 35, 116, -32, 6, -14, -100, -115, -128, -8, 10, 61, 98, 86, -8, 45, -49, -46, 90, -24, -81, 38]
            ],
            [
              3,
              [0, -62, 104, 108, -19, -10, 97, -26, 116, -58, 69, 110, 26, 87, 17, 89, 110, -57, 108, -6, 36, 21, 39, 87, 110, 102, -6, -43, -82, -125, -85, -82]
            ],
            [
              11,
              [-120, -101, 87, -112, 111, 15, -104, 127, 85, 25, -102, 81, 20, 58, 51, 75, -63, 116, -22, 0, 60, 30, 29, 30, -73, -115, 72, -9, -1, -53, 100, 124]
            ],
            [
              12,
              [41, -22, 106, 78, 31, 11, 114, -119, -19, 17, 92, 71, -122, 47, 62, 78, -67, -23, -55, -42, 53, 4, 47, -67, -55, -123, 6, 121, 34, -125, 64, -114]
            ],
            [
              13,
              [91, -34, -46, -63, 62, -34, 104, 82, 36, 41, -118, -3, 70, 15, -108, -48, -100, 45, 105, -85, -15, -61, -71, 43, -39, -94, -110, -55, -34, 89, -18, 38]
            ],
            [
              14,
              [76, 123, -40, 13, 51, -29, 72, -11, 59, -63, -18, -90, 103, 49, 23, -92, -85, -68, -62, -59, -100, -69, -7, 28, -58, 95, 69, 15, -74, 56, 54, 38]
            ]
          ] as [number, number[]][]
        const dataHashes = [[1, mrzHash], ...sampleDataHashes];
        const hashLen = 32;
        const formatted = formatAndConcatenateDataHashes(dataHashes, hashLen, offset);
        
    });

    it ("should compute hash to signed bytes", async function () {
        const hashSha1WithRSAEncryption = hash("sha1WithRSAEncryption", [1, 2, 3, 4, 5]);
        expect(hashSha1WithRSAEncryption).to.deep.equal(
            [
                17, -106, 106, -71, -64,
              -103,   -8,  -6, -66,  -6,
               -59,   76,   8, -43, -66,
                43,  -40, -55,   3, -81
            ]
        );

        const hashSHA384withECDSA = hash("SHA384withECDSA", [1, 2, 3, 4, 5]);
        expect(hashSHA384withECDSA).to.deep.equal(
            [
                -40, -120,  117, -37,   15,  119, -86,  -40,
                -13,  -39, -108,  -2,  104,  -51,  28,  -57,
                -20,   58,   79, -15,   67,  120, -73,   -2,
                -71, -111,  -27,  71, -124, -123,   1, -110,
                 20,   88,   84, -61,  110,   90,  64,  -96,
                -62,  -24,   13, -94,    0,   45, 124,  -56
              ]
        );

        const hashSha256WithRSAEncryption = hash("sha256WithRSAEncryption", [1, 2, 3, 4, 5]);
        expect(hashSha256WithRSAEncryption).to.deep.equal(
            [
                116,  -8,  31, -31,  103, -39, -101,
                 76, -76,  29, 109,   12, -51,  -88,
                 34, 120, -54, -18,  -97,  62,   47,
                 37, -43, -27, -93, -109, 111,  -13,
                -36, -20,  96, -48
              ]
        );

        const hashDefault = hash("default", [1, 2, 3, 4, 5]);
        expect(hashDefault).to.deep.equal(
            [
                116,  -8,  31, -31,  103, -39, -101,
                 76, -76,  29, 109,   12, -51,  -88,
                 34, 120, -54, -18,  -97,  62,   47,
                 37, -43, -27, -93, -109, 111,  -13,
                -36, -20,  96, -48
              ]
        );
    });

    it("should format sigAlg name for circuit", async function () {
        const formatted = formatSigAlgNameForCircuit("ecdsa-with-SHA256");
        expect(formatted).to.equal("ecdsa_with_SHA256");

        const formatted2 = formatSigAlgNameForCircuit("ecdsa-with-SHA256", "3");
        expect(formatted2).to.equal("ecdsa_with_SHA256_3");
    });

    it("should convert big int to chunk bytes", async function () {
        const res = bigIntToChunkedBytes(BigInt(1234567890), 3, 4);
        expect(res).to.deep.equal([ '2', '2', '3', '1' ]);
    });

});
