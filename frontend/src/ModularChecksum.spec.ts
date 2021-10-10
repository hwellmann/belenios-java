import { BigInteger } from "jsbn";
import { checksum } from "./ModularChecksum";

const q = new BigInteger("78571733251071885079927659812671450121821421258408794611510081919805623223441");


describe('GenerateCredentials', () => {

    test('should compute checksum mod 17', () => {
        expect(checksum("Hello world!", new BigInteger("17")).toString()).toEqual("5");
    });

    test('should compute checksum mod 1', () => {
        expect(checksum("General Election", q).toString()).toEqual("21975804506769217954373109906108369112774727951412621094989250905673600375274");
    });

    test('', () => {
        console.log([[1, 2],[3, 4]].flatMap(i => i));
    });
});
