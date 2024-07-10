import { assert, expect } from 'chai'
import path from "path";
import { shaPad } from "../src/utils/shaPad";

describe("Hash padding", function () {


    it("should compute padded sha256", async function () {
        const testArray = new Uint8Array(32);
        testArray[0] = 1;
        const padded = shaPad("sha256WithRSAEncryption", testArray, 64);
        assert.equal(padded[0].length, 64);
        expect(padded[0], "should be equal").to.deep.equal(new Uint8Array(
          [
            1, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0,
            0, 0, 1, 0
          ]));
        expect(padded[1], "should be equal").to.equal(64);
    });
});
