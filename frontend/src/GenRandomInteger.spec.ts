import { BigInteger } from 'jsbn';
import { random } from './GenRandomInteger';

describe('GenerateRandomInteger', () => {

    test('should generate random BigInteger', () => {
        const q = 13;
        const Q = new BigInteger(q.toString());
        for (var i: number = 0; i < 100; i++) {
            expect(parseInt(random(Q).toString())).toBeLessThan(q);
        }
    });
});
