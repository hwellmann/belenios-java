import { RandomGenerator } from 'jsbn';

declare module "jsbn" {
    export class SecureRandom implements RandomGenerator {
        nextBytes(bytes: number[]): void;
    }
}



