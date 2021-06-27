/*
 * Copyright (C) 2020 Berner Fachhochschule https://e-voting.bfh.ch
 *
 *  - This program is free software: you can redistribute it and/or modify                           -
 *  - it under the terms of the GNU Affero General Public License as published by                    -
 *  - the Free Software Foundation, either version 3 of the License, or                              -
 *  - (at your option) any later version.                                                            -
 *  -                                                                                                -
 *  - This program is distributed in the hope that it will be useful,                                -
 *  - but WITHOUT ANY WARRANTY; without even the implied warranty of                                 -
 *  - MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the                                   -
 *  - GNU General Public License for more details.                                                   -
 *  -                                                                                                -
 *  - You should have received a copy of the GNU Affero General Public License                       -
 *  - along with this program. If not, see <http://www.gnu.org/licenses/>.                           -
 */
package org.omadac.vote.belenios.algo;

import java.math.BigInteger;
import java.security.SecureRandom;

public class GenRandomInteger {

    private static SecureRandom random = new SecureRandom();

    public static BigInteger run(BigInteger q) {

        // PREPARATION
        BigInteger r;

        int l = q.bitLength();

        // ALGORITHM
        do {
            r = new BigInteger(l, random);
        } while (r.compareTo(q) >= 0);
        return r;
    }

    public static int run(int q) {
        return run(BigInteger.valueOf(q)).intValue();
    }
}
