/*
 * This class was taken from the open source OpenJDK project and modified to work 
 * in apex.
 * 
 * @author Nate Wallace
 */

/*
 * Copyright 1997-2007 Sun Microsystems, Inc.  All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Sun designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Sun in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 */

/**
 * This is the internal DES class responsible for encryption and
 * decryption of a byte array of size 8.
 *
 * @author Gigi Ankeny
 * @author Jan Luehe
 */
public class DESCrypt {

    /*
     * The DES block size.
     */
    private static final integer DES_BLOCK_SIZE = 8;
    
    /*
     * Table used in the DES calculation.
     */
    private static final integer[] s0p = new integer[] {
        4260096, 65536, 1077936128, 1078001920, 4194304,
        1073807616, 1073807360, 1077936128, 1073807616, 4260096,
        4259840, 1073742080, 1077936384, 4194304, 0,
        1073807360, 65536, 1073741824, 4194560, 65792,
        1078001920, 4259840, 1073742080, 4194560, 1073741824,
        256, 65792, 1078001664, 256, 1077936384,
        1078001664, 0, 0, 1078001920, 4194560,
        1073807360, 4260096, 65536, 1073742080, 4194560,
        1078001664, 256, 65792, 1077936128, 1073807616,
        1073741824, 1077936128, 4259840, 1078001920, 65792,
        4259840, 1077936384, 4194304, 1073742080, 1073807360,
        0, 65536, 4194304, 1077936384, 4260096,
        1073741824, 1078001664, 256, 1073807616
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] s1p = new integer[] {
        134352898, 0, 135168, 134348800, 134217730,
        4098, 134221824, 135168, 4096, 134348802,
        2, 134221824, 131074, 134352896, 134348800,
        2, 131072, 134221826, 134348802, 4096,
        135170, 134217728, 0, 131074, 134221826,
        135170, 134352896, 134217730, 134217728, 131072,
        4098, 134352898, 131074, 134352896, 134221824,
        135170, 134352898, 131074, 134217730, 0,
        134217728, 4098, 131072, 134348802, 4096,
        134217728, 135170, 134221826, 134352896, 4096,
        0, 134217730, 2, 134352898, 135168,
        134348800, 134348802, 131072, 4098, 134221824,
        134221826, 2, 134348800, 135168
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] s2p = new integer[] {
        545259520, 8421408, 32, 545259552, 536903680,
        8388608, 545259552, 32800, 8388640, 32768,
        8421376, 536870912, 545292320, 536870944, 536870912,
        545292288, 0, 536903680, 8421408, 32,
        536870944, 545292320, 32768, 545259520, 545292288,
        8388640, 536903712, 8421376, 32800, 0,
        8388608, 536903712, 8421408, 32, 536870912,
        32768, 536870944, 536903680, 8421376, 545259552,
        0, 8421408, 32800, 545292288, 536903680,
        8388608, 545292320, 536870912, 536903712, 545259520,
        8388608, 545292320, 32768, 8388640, 545259552,
        32800, 8388640, 0, 545292288, 536870944,
        545259520, 536903712, 32, 8421376
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] s3p = new integer[] {
        524801, 33554944, 1, 34079233, 0,
        34078720, 33554945, 524289, 34079232, 33554433,
        33554432, 513, 33554433, 524801, 524288,
        33554432, 34078721, 524800, 512, 1,
        524800, 33554945, 34078720, 512, 513,
        0, 524289, 34079232, 33554944, 34078721,
        34079233, 524288, 34078721, 513, 524288,
        33554433, 524800, 33554944, 1, 34078720,
        33554945, 0, 512, 524289, 0,
        34078721, 34079232, 512, 33554432, 34079233,
        524801, 524288, 34079233, 1, 33554944,
        524801, 524289, 524800, 34078720, 33554945,
        513, 33554432, 33554433, 34079232
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] s4p = new integer[] {
        16777216, 8192, 128, 16785540, 16785412,
        16777344, 8324, 16785408, 8192, 4,
        16777220, 8320, 16777348, 16785412, 16785536,
        0, 8320, 16777216, 8196, 132,
        16777344, 8324, 0, 16777220, 4,
        16777348, 16785540, 8196, 16785408, 128,
        132, 16785536, 16785536, 16777348, 8196,
        16785408, 8192, 4, 16777220, 16777344,
        16777216, 8320, 16785540, 0, 8324,
        16777216, 128, 8196, 16777348, 128,
        0, 16785540, 16785412, 16785536, 132,
        8192, 8320, 16785412, 16777344, 132,
        4, 8324, 16785408, 16777220
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] s5p = new integer[] {
        268435464, 262152, 0, 268698624, 262152,
        1024, 268436488, 262144, 1032, 268698632,
        263168, 268435456, 268436480, 268435464, 268697600,
        263176, 262144, 268436488, 268697608, 0,
        1024, 8, 268698624, 268697608, 268698632,
        268697600, 268435456, 1032, 8, 263168,
        263176, 268436480, 1032, 268435456, 268436480,
        263176, 268698624, 262152, 0, 268436480,
        268435456, 1024, 268697608, 262144, 262152,
        268698632, 263168, 8, 268698632, 263168,
        262144, 268436488, 268435464, 268697600, 263176,
        0, 1024, 268435464, 268436488, 268698624,
        268697600, 1032, 8, 268697608
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] s6p = new integer[] {
        2048, 64, 2097216, -2145386496, -2145384384,
        -2147481600, 2112, 0, 2097152, -2145386432,
        -2147483584, 2099200, -2147483647-1, 2099264, 2099200,
        -2147483584, -2145386432, 2048, -2147481600, -2145384384,
        0, 2097216, -2145386496, 2112, -2145384448,
        -2147481536, 2099264, -2147483647-1, -2147481536, -2145384448,
        64, 2097152, -2147481536, 2099200, -2145384448,
        -2147483584, 2048, 64, 2097152, -2145384448,
        -2145386432, -2147481536, 2112, 0, 64,
        -2145386496, -2147483647-1, 2097216, 0, -2145386432,
        2097216, 2112, -2147483584, 2048, -2145384384,
        2097152, 2099264, -2147483647-1, -2147481600, -2145384384,
        -2145386496, 2099264, 2099200, -2147481600
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] s7p = new integer[] {
        68157456, 68173824, 16400, 0, 67125248,
        1048592, 68157440, 68173840, 16, 67108864,
        1064960, 16400, 1064976, 67125264, 67108880,
        68157440, 16384, 1064976, 1048592, 67125248,
        68173840, 67108880, 0, 1064960, 67108864,
        1048576, 67125264, 68157456, 1048576, 16384,
        68173824, 16, 1048576, 16384, 67108880,
        68173840, 16400, 67108864, 0, 1064960,
        68157456, 67125264, 67125248, 1048592, 68173824,
        16, 1048592, 67125248, 68173840, 1048576,
        68157440, 67108880, 1064960, 16400, 67125264,
        68157440, 16, 68173824, 1064976, 0,
        67108864, 68157456, 16384, 1064976
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permRight0 = new integer[] {
        0, 1073741824, 4194304, 1077936128, 16384,
        1073758208, 4210688, 1077952512, 64, 1073741888,
        4194368, 1077936192, 16448, 1073758272, 4210752,
        1077952576
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permLeft1 = new integer[] {
        0, 1073741824, 4194304, 1077936128, 16384,
        1073758208, 4210688, 1077952512, 64, 1073741888,
        4194368, 1077936192, 16448, 1073758272, 4210752,
        1077952576
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permRight2 = new integer[] {
        0, 268435456, 1048576, 269484032, 4096,
        268439552, 1052672, 269488128, 16, 268435472,
        1048592, 269484048, 4112, 268439568, 1052688,
        269488144
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permLeft3 = new integer[] {
        0, 268435456, 1048576, 269484032, 4096,
        268439552, 1052672, 269488128, 16, 268435472,
        1048592, 269484048, 4112, 268439568, 1052688,
        269488144
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permRight4 = new integer[] {
        0, 67108864, 262144, 67371008, 1024,
        67109888, 263168, 67372032, 4, 67108868,
        262148, 67371012, 1028, 67109892, 263172,
        67372036
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permLeft5 = new integer[] {
        0, 67108864, 262144, 67371008, 1024,
        67109888, 263168, 67372032, 4, 67108868,
        262148, 67371012, 1028, 67109892, 263172,
        67372036
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permRight6 = new integer[] {
        0, 16777216, 65536, 16842752, 256,
        16777472, 65792, 16843008, 1, 16777217,
        65537, 16842753, 257, 16777473, 65793,
        16843009
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permLeft7 = new integer[] {
        0, 16777216, 65536, 16842752, 256,
        16777472, 65792, 16843008, 1, 16777217,
        65537, 16842753, 257, 16777473, 65793,
        16843009
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permRight8 = new integer[] {
        0, -2147483647-1, 8388608, -2139095040, 32768,
        -2147450880, 8421376, -2139062272, 128, -2147483520,
        8388736, -2139094912, 32896, -2147450752, 8421504,
        -2139062144
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permLeft9 = new integer[] {
        0, -2147483647-1, 8388608, -2139095040, 32768,
        -2147450880, 8421376, -2139062272, 128, -2147483520,
        8388736, -2139094912, 32896, -2147450752, 8421504,
        -2139062144
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permRightA = new integer[] {
        0, 536870912, 2097152, 538968064, 8192,
        536879104, 2105344, 538976256, 32, 536870944,
        2097184, 538968096, 8224, 536879136, 2105376,
        538976288
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permLeftB = new integer[] {
        0, 536870912, 2097152, 538968064, 8192,
        536879104, 2105344, 538976256, 32, 536870944,
        2097184, 538968096, 8224, 536879136, 2105376,
        538976288
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permRightC = new integer[] {
        0, 134217728, 524288, 134742016, 2048,
        134219776, 526336, 134744064, 8, 134217736,
        524296, 134742024, 2056, 134219784, 526344,
        134744072
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permLeftD = new integer[] {
        0, 134217728, 524288, 134742016, 2048,
        134219776, 526336, 134744064, 8, 134217736,
        524296, 134742024, 2056, 134219784, 526344,
        134744072
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permRightE = new integer[] {
        0, 33554432, 131072, 33685504, 512,
        33554944, 131584, 33686016, 2, 33554434,
        131074, 33685506, 514, 33554946, 131586,
        33686018
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] permLeftF = new integer[] {
        0, 33554432, 131072, 33685504, 512,
        33554944, 131584, 33686016, 2, 33554434,
        131074, 33685506, 514, 33554946, 131586,
        33686018
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft0 = new integer[] {
       0, 32768, 0, 32768, 128,
       32896, 128, 32896, 0, 32768,
       0, 32768, 128, 32896, 128,
       32896
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight0 = new integer[] {
       0, 0, 32768, 32768, 0,
       0, 32768, 32768, 128, 128,
       32896, 32896, 128, 128, 32896,
       32896
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft1 = new integer[] {
       0, -2147483647-1, 0, -2147483647-1, 8388608,
       -2139095040, 8388608, -2139095040, 0, -2147483647-1,
       0, -2147483647-1, 8388608, -2139095040, 8388608,
       -2139095040
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight1 = new integer[] {
       0, 0, -2147483647-1, -2147483647-1, 0,
       0, -2147483647-1, -2147483647-1, 8388608, 8388608,
       -2139095040, -2139095040, 8388608, 8388608, -2139095040,
       -2139095040
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft2 = new integer[] {
       0, 16384, 0, 16384, 64,
       16448, 64, 16448, 0, 16384,
       0, 16384, 64, 16448, 64,
       16448
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight2 = new integer[] {
       0, 0, 16384, 16384, 0,
       0, 16384, 16384, 64, 64,
       16448, 16448, 64, 64, 16448,
       16448
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft3 = new integer[] {
       0, 1073741824, 0, 1073741824, 4194304,
       1077936128, 4194304, 1077936128, 0, 1073741824,
       0, 1073741824, 4194304, 1077936128, 4194304,
       1077936128
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight3 = new integer[] {
       0, 0, 1073741824, 1073741824, 0,
       0, 1073741824, 1073741824, 4194304, 4194304,
       1077936128, 1077936128, 4194304, 4194304, 1077936128,
       1077936128
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft4 = new integer[] {
       0, 8192, 0, 8192, 32,
       8224, 32, 8224, 0, 8192,
       0, 8192, 32, 8224, 32,
       8224
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight4 = new integer[] {
       0, 0, 8192, 8192, 0,
       0, 8192, 8192, 32, 32,
       8224, 8224, 32, 32, 8224,
       8224
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft5 = new integer[] {
       0, 536870912, 0, 536870912, 2097152,
       538968064, 2097152, 538968064, 0, 536870912,
       0, 536870912, 2097152, 538968064, 2097152,
       538968064
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight5 = new integer[] {
       0, 0, 536870912, 536870912, 0,
       0, 536870912, 536870912, 2097152, 2097152,
       538968064, 538968064, 2097152, 2097152, 538968064,
       538968064
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft6 = new integer[] {
       0, 4096, 0, 4096, 16,
       4112, 16, 4112, 0, 4096,
       0, 4096, 16, 4112, 16,
       4112
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight6 = new integer[] {
       0, 0, 4096, 4096, 0,
       0, 4096, 4096, 16, 16,
       4112, 4112, 16, 16, 4112,
       4112
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft7 = new integer[] {
       0, 268435456, 0, 268435456, 1048576,
       269484032, 1048576, 269484032, 0, 268435456,
       0, 268435456, 1048576, 269484032, 1048576,
       269484032
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight7 = new integer[] {
       0, 0, 268435456, 268435456, 0,
       0, 268435456, 268435456, 1048576, 1048576,
       269484032, 269484032, 1048576, 1048576, 269484032,
       269484032
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft8 = new integer[] {
       0, 2048, 0, 2048, 8,
       2056, 8, 2056, 0, 2048,
       0, 2048, 8, 2056, 8,
       2056
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight8 = new integer[] {
       0, 0, 2048, 2048, 0,
       0, 2048, 2048, 8, 8,
       2056, 2056, 8, 8, 2056,
       2056
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeft9 = new integer[] {
       0, 134217728, 0, 134217728, 524288,
       134742016, 524288, 134742016, 0, 134217728,
       0, 134217728, 524288, 134742016, 524288,
       134742016
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRight9 = new integer[] {
       0, 0, 134217728, 134217728, 0,
       0, 134217728, 134217728, 524288, 524288,
       134742016, 134742016, 524288, 524288, 134742016,
       134742016
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeftA = new integer[] {
       0, 1024, 0, 1024, 4,
       1028, 4, 1028, 0, 1024,
       0, 1024, 4, 1028, 4,
       1028
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRightA = new integer[] {
       0, 0, 1024, 1024, 0,
       0, 1024, 1024, 4, 4,
       1028, 1028, 4, 4, 1028,
       1028
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeftB = new integer[] {
       0, 67108864, 0, 67108864, 262144,
       67371008, 262144, 67371008, 0, 67108864,
       0, 67108864, 262144, 67371008, 262144,
       67371008
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRightB = new integer[] {
       0, 0, 67108864, 67108864, 0,
       0, 67108864, 67108864, 262144, 262144,
       67371008, 67371008, 262144, 262144, 67371008,
       67371008
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeftC = new integer[] {
       0, 512, 0, 512, 2,
       514, 2, 514, 0, 512,
       0, 512, 2, 514, 2,
       514
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRightC = new integer[] {
       0, 0, 512, 512, 0,
       0, 512, 512, 2, 2,
       514, 514, 2, 2, 514,
       514
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeftD = new integer[] {
       0, 33554432, 0, 33554432, 131072,
       33685504, 131072, 33685504, 0, 33554432,
       0, 33554432, 131072, 33685504, 131072,
       33685504
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRightD = new integer[] {
       0, 0, 33554432, 33554432, 0,
       0, 33554432, 33554432, 131072, 131072,
       33685504, 33685504, 131072, 131072, 33685504,
       33685504
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeftE = new integer[] {
       0, 256, 0, 256, 1,
       257, 1, 257, 0, 256,
       0, 256, 1, 257, 1,
       257
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRightE = new integer[] {
       0, 0, 256, 256, 0,
       0, 256, 256, 1, 1,
       257, 257, 1, 1, 257,
       257
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermLeftF = new integer[] {
       0, 16777216, 0, 16777216, 65536,
       16842752, 65536, 16842752, 0, 16777216,
       0, 16777216, 65536, 16842752, 65536,
       16842752
    };

    /*
     * Table used in the DES calculation.
     */
    private static final integer[] initPermRightF = new integer[] {
       0, 0, 16777216, 16777216, 0,
       0, 16777216, 16777216, 65536, 65536,
       16842752, 16842752, 65536, 65536, 16842752,
       16842752
    };

    /*
     * Holds the encryption key array after expansion and permutation
     */
    private integer[] expandedKey = null;

    /*
     * Initializes this object.
     * 
     * @param rawKey The key to use for the encrypt operation.
     */
    private void init(integer[] rawKey) {
        if (rawKey == null)
            throw new RuntimeException('rawKey is null.');
        if (rawKey.size() != DES_BLOCK_SIZE) {
            throw new RuntimeException('Wrong key size');
        }
        expandKey(rawKey);
    }
    
    /*
     * Performs the encryption operation.
     *
     * @param key The key to use to encrypt the data.
     * @param plain The uncrypted data that will be encrypted.
     * @return The encrypted data.
     */
    public integer[] encrypt(integer[] key, integer[] plain) {
        init(key);
        return encrypt(plain);
    }  
    
    /*
     * Performs the encryption operation.
     *
     * @param plain The uncrypted data that will be encrypted.
     * @return The encrypted data.
     */
    private integer[] encrypt(integer[] plain) {
        if (plain == null)
            throw new RuntimeException('plain is null.');
        if (Math.mod(plain.size(), DES_BLOCK_SIZE) != 0)
            throw new RuntimeException('plain.size() is not a multiple of ' + String.valueOf(DES_BLOCK_SIZE));
            
        integer[] result = new integer[plain.size()];
        for (integer i = 0; i < plain.size(); i += 8)
            encryptBlock(plain, i, result, i);
        
        return result;
    }    

    /*
      * Performs encryption operation.
      *
      * <p>The input plain text <code>plain</code>, starting at
      * <code>plainOffset</code> and ending at
      * <code>(plainOffset + len - 1)</code>, is encrypted.
      * The result is stored in <code>cipher</code>, starting at
      * <code>cipherOffset</code>.
      *
      * <p>The subclass that implements Cipher should ensure that
      * <code>init</code> has been called before this method is called.
      *
      * @param plain the buffer with the input data to be encrypted
      * @param plainOffset the offset in <code>plain</code>
      * @param plainLen the length of the input data
      * @param cipher the buffer for the result
      * @param cipherOffset the offset in <code>cipher</code>
      *
      * @exception RuntimeException if the input length is different
      * from the cipher's block size
      */
    private void encryptBlock(integer[] plain, integer plainOffset, integer[] cipher, integer cipherOffset) {
        cipherBlock(plain, plainOffset, cipher, cipherOffset);
    }    

    /*
     * Encrypt a block of data.
     *
     * @param input The block of data to read data from that will be encrypted.
     * @param inOffset The offest to start reading data from in input.
     * @param out The array that accepts the resulting encrpyted data.
     * @param outOffset The offset to start writing encrypted data to in out.
     */
    private void cipherBlock(integer[] input, integer inOffset, integer[] out, integer outOffset) {
        integer[] key;
        integer temp;
        integer i, j;
        integer offset;
        integer left, right;

        left = initialPermutationLeft(input, inOffset);
        right = initialPermutationRight(input, inOffset);

        key = expandedKey;
        offset = 0 - DES_BLOCK_SIZE;
        j = 0;
        
        for (i = 0; i < 16; i++) {
            // make the first and last bit adjacent
            // move the first bit to the last
            temp = (right << 1) | ((right >> 31) & 1);

            // mangler function:
            // every 6 bit is fed into the sbox, which
            // produces 4-bit output            
            left ^= ((((((s0p[(integer)((temp & 63) ^ key[j+0])]
                ^ s1p[(integer)(((temp >>  4) & 63) ^ key[j+1])])
                ^ s2p[(integer)(((temp >>  8) & 63) ^ key[j+2])])
                ^ s3p[(integer)(((temp >> 12) & 63) ^ key[j+3])])
                ^ s4p[(integer)(((temp >> 16) & 63) ^ key[j+4])])
                ^ s5p[(integer)(((temp >> 20) & 63) ^ key[j+5])])
                ^ s6p[(integer)(((temp >> 24) & 63) ^ key[j+6])]);            

            // make the last sbox input the last bit from right[0]
            temp = ((right & 1) << 5) | ((right >> 27) & 31);
            left ^= s7p[(integer)(temp ^ key[j+7])];
            temp = left;
            left = right;
            right = temp;
            j -= offset;
        }

        temp = left;
        left = right;
        right = temp;
        perm(left, right, out, outOffset);
    }

    /*
     * Perform permutation operation.
     *
     * @param left The left side of the permutation operation input.
     * @param right The right side of the permutation operation input.
     * @param out The array that accepts the results of the permutation operation.
     * @param offset The offest to start writing the permutation results at in out.
     */
    private static void perm(integer left, integer right, integer[] out, integer offset) {
        integer low, high, temp;

        temp = left;
        high = permRight0[temp & 15];
        temp >>= 4;
        low  = permLeft1[temp & 15];
        temp >>= 4;
        high |= permRight2[temp & 15];
        temp >>= 4;
        low  |= permLeft3[temp & 15];
        temp >>= 4;
        high |= permRight4[temp & 15];
        temp >>= 4;
        low  |= permLeft5[temp & 15];
        temp >>= 4;
        high |= permRight6[temp & 15];
        temp >>= 4;
        low  |= permLeft7[temp & 15];

        temp = right;
        high |= permRight8[temp & 15];
        temp >>= 4;
        low  |= permLeft9[temp & 15];
        temp >>= 4;
        high |= permRightA[temp & 15];
        temp >>= 4;
        low  |= permLeftB[temp & 15];
        temp >>= 4;
        high |= permRightC[temp & 15];
        temp >>= 4;
        low  |= permLeftD[temp & 15];
        temp >>= 4;
        high |= permRightE[temp & 15];
        temp >>= 4;
        low  |= permLeftF[temp & 15];


        out[offset + 0] = low & 255;
        out[offset + 1] = (low >> 8) & 255;
        out[offset + 2] = (low >> 16) & 255;
        out[offset + 3] = (low >> 24) & 255;
        out[offset + 4] = high & 255;
        out[offset + 5] = (high >> 8) & 255;
        out[offset + 6] = (high >> 16) & 255;
        out[offset + 7] = (high >> 24) & 255;

    }

    /*
     * Performs the initial permutation operation on the left side.
     *
     * @param block The data to use as the input for the initial permutation on the left side.
     * @param offset The offset in the block to start reading data from.
     * @return The result of the initial permutation operation on the left side.
     */
    private static integer initialPermutationLeft(integer[] block, integer offset) {
        integer l;

        l  = initPermLeft1[block[offset] & 15];
        l |= initPermLeft0[(block[offset] >> 4) & 15];
        l |= initPermLeft3[block[offset + 1] & 15];
        l |= initPermLeft2[(block[offset + 1] >> 4) & 15];
        l |= initPermLeft5[block[offset + 2] & 15];
        l |= initPermLeft4[(block[offset + 2] >> 4) & 15];
        l |= initPermLeft7[block[offset + 3] & 15];
        l |= initPermLeft6[(block[offset + 3] >> 4) & 15];
        l |= initPermLeft9[block[offset + 4] & 15];
        l |= initPermLeft8[(block[offset + 4] >> 4) & 15];
        l |= initPermLeftB[block[offset + 5] & 15];
        l |= initPermLeftA[(block[offset + 5] >> 4) & 15];
        l |= initPermLeftD[block[offset + 6] & 15];
        l |= initPermLeftC[(block[offset + 6] >> 4) & 15];
        l |= initPermLeftF[block[offset + 7] & 15];
        l |= initPermLeftE[(block[offset + 7] >> 4) & 15];
        return l;
    }

    /*
     * Performs the initial permutation operation on the right side.
     *
     * @param block The data to use as the input for the initial permutation on the right side.
     * @param offset The offset in the block to start reading data from.
     * @return The result of the initial permutation operation on the right side.
     */ 
    private static integer initialPermutationRight(integer[] block, integer offset) {
        integer l;

        l  = initPermRight1[block[offset] & 15];
        l |= initPermRight0[(block[offset] >> 4) & 15];
        l |= initPermRight3[block[offset + 1] & 15];
        l |= initPermRight2[(block[offset + 1] >> 4) & 15];
        l |= initPermRight5[block[offset + 2] & 15];
        l |= initPermRight4[(block[offset + 2] >> 4) & 15];
        l |= initPermRight7[block[offset + 3] & 15];
        l |= initPermRight6[(block[offset + 3] >> 4) & 15];
        l |= initPermRight9[block[offset + 4] & 15];
        l |= initPermRight8[(block[offset + 4] >> 4) & 15];
        l |= initPermRightB[block[offset + 5] & 15];
        l |= initPermRightA[(block[offset + 5] >> 4) & 15];
        l |= initPermRightD[block[offset + 6] & 15];
        l |= initPermRightC[(block[offset + 6] >> 4) & 15];
        l |= initPermRightF[block[offset + 7] & 15];
        l |= initPermRightE[(block[offset + 7] >> 4) & 15];
        return l;
    }

    /*
     * Expand a raw key for use as a DES key.  The results of this is stored in the expandedKey field of this object.
     *
     * @param key The raw key to expand.
     */
    private void expandKey(integer[] key) {
        integer octet;
        integer[] ek = new integer[128];
        for (integer i = 0; i < ek.size(); i++)
            ek[i] = 0;

        octet = key[0];
        if ((octet & 128) != 0) {
            ek[  3] |=  2; ek[  9] |=  8; ek[ 18] |=  8;
            ek[ 27] |= 32; ek[ 33] |=  2; ek[ 42] |= 16;
            ek[ 48] |=  8; ek[ 65] |= 16; ek[ 74] |=  2;
            ek[ 80] |=  2; ek[ 89] |=  4; ek[ 99] |= 16;
            ek[104] |=  4; ek[122] |= 32;
        }
        if ((octet & 64) != 0) {
            ek[  1] |=  4; ek[  8] |=  1; ek[ 18] |=  4;
            ek[ 25] |= 32; ek[ 34] |= 32; ek[ 41] |=  8;
            ek[ 50] |=  8; ek[ 59] |= 32; ek[ 64] |= 16;
            ek[ 75] |=  4; ek[ 90] |=  1; ek[ 97] |= 16;
            ek[106] |=  2; ek[112] |=  2; ek[123] |=  1;
        }
        if ((octet & 32) != 0) {
            ek[  2] |=  1; ek[ 19] |=  8; ek[ 35] |=  1;
            ek[ 40] |=  1; ek[ 50] |=  4; ek[ 57] |= 32;
            ek[ 75] |=  2; ek[ 80] |= 32; ek[ 89] |=  1;
            ek[ 96] |= 16; ek[107] |=  4; ek[120] |=  8;
        }
        if ((octet & 16) != 0) {
            ek[  4] |= 32; ek[ 20] |=  2; ek[ 31] |=  4;
            ek[ 37] |= 32; ek[ 47] |=  1; ek[ 54] |=  1;
            ek[ 63] |=  2; ek[ 68] |=  1; ek[ 78] |=  4;
            ek[ 84] |=  8; ek[101] |= 16; ek[108] |=  4;
            ek[119] |= 16; ek[126] |=  8;
        }
        if ((octet & 8) != 0) {
            ek[  5] |=  4; ek[ 15] |=  4; ek[ 21] |= 32;
            ek[ 31] |=  1; ek[ 38] |=  1; ek[ 47] |=  2;
            ek[ 53] |=  2; ek[ 68] |=  8; ek[ 85] |= 16;
            ek[ 92] |=  4; ek[103] |= 16; ek[108] |= 32;
            ek[118] |= 32; ek[124] |=  2;
        }
        if ((octet & 4) != 0) {
            ek[ 15] |=  2; ek[ 21] |=  2; ek[ 39] |=  8;
            ek[ 46] |= 16; ek[ 55] |= 32; ek[ 61] |=  1;
            ek[ 71] |= 16; ek[ 76] |= 32; ek[ 86] |= 32;
            ek[ 93] |=  4; ek[102] |=  2; ek[108] |= 16;
            ek[117] |=  8; ek[126] |=  1;
        }
        if ((octet & 2) != 0) {
            ek[ 14] |= 16; ek[ 23] |= 32; ek[ 29] |=  1;
            ek[ 38] |=  8; ek[ 52] |=  2; ek[ 63] |=  4;
            ek[ 70] |=  2; ek[ 76] |= 16; ek[ 85] |=  8;
            ek[100] |=  1; ek[110] |=  4; ek[116] |=  8;
            ek[127] |=  8;
        }
        octet = key[1];
        if ((octet & 128) != 0) {
            ek[  1] |=  8; ek[  8] |= 32; ek[ 17] |=  1;
            ek[ 24] |= 16; ek[ 35] |=  4; ek[ 50] |=  1;
            ek[ 57] |= 16; ek[ 67] |=  8; ek[ 83] |=  1;
            ek[ 88] |=  1; ek[ 98] |=  4; ek[105] |= 32;
            ek[114] |= 32; ek[123] |=  2;
        }
        if ((octet & 64) != 0) {
            ek[  0] |=  1; ek[ 11] |= 16; ek[ 16] |=  4;
            ek[ 35] |=  2; ek[ 40] |= 32; ek[ 49] |=  1;
            ek[ 56] |= 16; ek[ 65] |=  2; ek[ 74] |= 16;
            ek[ 80] |=  8; ek[ 99] |=  8; ek[115] |=  1;
            ek[121] |=  4;
        }
        if ((octet & 32) != 0) {
            ek[  9] |= 16; ek[ 18] |=  2; ek[ 24] |=  2;
            ek[ 33] |=  4; ek[ 43] |= 16; ek[ 48] |=  4;
            ek[ 66] |= 32; ek[ 73] |=  8; ek[ 82] |=  8;
            ek[ 91] |= 32; ek[ 97] |=  2; ek[106] |= 16;
            ek[112] |=  8; ek[122] |=  1;
        }
        if ((octet & 16) != 0) {
            ek[ 14] |= 32; ek[ 21] |=  4; ek[ 30] |=  2;
            ek[ 36] |= 16; ek[ 45] |=  8; ek[ 60] |=  1;
            ek[ 69] |=  2; ek[ 87] |=  8; ek[ 94] |= 16;
            ek[103] |= 32; ek[109] |=  1; ek[118] |=  8;
            ek[124] |= 32;
        }
        if ((octet & 8) != 0) {
            ek[  7] |=  4; ek[ 14] |=  2; ek[ 20] |= 16;
            ek[ 29] |=  8; ek[ 44] |=  1; ek[ 54] |=  4;
            ek[ 60] |=  8; ek[ 71] |=  8; ek[ 78] |= 16;
            ek[ 87] |= 32; ek[ 93] |=  1; ek[102] |=  8;
            ek[116] |=  2; ek[125] |=  4;
        }
        if ((octet & 4) != 0) {
            ek[  7] |=  2; ek[ 12] |=  1; ek[ 22] |=  4;
            ek[ 28] |=  8; ek[ 45] |= 16; ek[ 52] |=  4;
            ek[ 63] |= 16; ek[ 70] |=  8; ek[ 84] |=  2;
            ek[ 95] |=  4; ek[101] |= 32; ek[111] |=  1;
            ek[118] |=  1;
        }
        if ((octet & 2) != 0) {
            ek[  6] |= 16; ek[ 13] |= 16; ek[ 20] |=  4;
            ek[ 31] |= 16; ek[ 36] |= 32; ek[ 46] |= 32;
            ek[ 53] |=  4; ek[ 62] |=  2; ek[ 69] |= 32;
            ek[ 79] |=  1; ek[ 86] |=  1; ek[ 95] |=  2;
            ek[101] |=  2; ek[119] |=  8;
        }
        octet = key[2];
        if ((octet & 128) != 0) {
            ek[  0] |= 32; ek[ 10] |=  8; ek[ 19] |= 32;
            ek[ 25] |=  2; ek[ 34] |= 16; ek[ 40] |=  8;
            ek[ 59] |=  8; ek[ 66] |=  2; ek[ 72] |=  2;
            ek[ 81] |=  4; ek[ 91] |= 16; ek[ 96] |=  4;
            ek[115] |=  2; ek[121] |=  8;
        }
        if ((octet & 64) != 0) {
            ek[  3] |= 16; ek[ 10] |=  4; ek[ 17] |= 32;
            ek[ 26] |= 32; ek[ 33] |=  8; ek[ 42] |=  8;
            ek[ 51] |= 32; ek[ 57] |=  2; ek[ 67] |=  4;
            ek[ 82] |=  1; ek[ 89] |= 16; ek[ 98] |=  2;
            ek[104] |=  2; ek[113] |=  4; ek[120] |=  1;
        }
        if ((octet & 32) != 0) {
            ek[  1] |= 16; ek[ 11] |=  8; ek[ 27] |=  1;
            ek[ 32] |=  1; ek[ 42] |=  4; ek[ 49] |= 32;
            ek[ 58] |= 32; ek[ 67] |=  2; ek[ 72] |= 32;
            ek[ 81] |=  1; ek[ 88] |= 16; ek[ 99] |=  4;
            ek[114] |=  1;
        }
        if ((octet & 16) != 0) {
            ek[  6] |= 32; ek[ 12] |=  2; ek[ 23] |=  4;
            ek[ 29] |= 32; ek[ 39] |=  1; ek[ 46] |=  1;
            ek[ 55] |=  2; ek[ 61] |=  2; ek[ 70] |=  4;
            ek[ 76] |=  8; ek[ 93] |= 16; ek[100] |=  4;
            ek[111] |= 16; ek[116] |= 32;
        }
        if ((octet & 8) != 0) {
            ek[  6] |=  2; ek[ 13] |= 32; ek[ 23] |=  1;
            ek[ 30] |=  1; ek[ 39] |=  2; ek[ 45] |=  2;
            ek[ 63] |=  8; ek[ 77] |= 16; ek[ 84] |=  4;
            ek[ 95] |= 16; ek[100] |= 32; ek[110] |= 32;
            ek[117] |=  4; ek[127] |=  4;
        }
        if ((octet & 4) != 0) {
            ek[  4] |=  1; ek[ 13] |=  2; ek[ 31] |=  8;
            ek[ 38] |= 16; ek[ 47] |= 32; ek[ 53] |=  1;
            ek[ 62] |=  8; ek[ 68] |= 32; ek[ 78] |= 32;
            ek[ 85] |=  4; ek[ 94] |=  2; ek[100] |= 16;
            ek[109] |=  8; ek[127] |=  2;
        }
        if ((octet & 2) != 0) {
            ek[  5] |= 16; ek[ 15] |= 32; ek[ 21] |=  1;
            ek[ 30] |=  8; ek[ 44] |=  2; ek[ 55] |=  4;
            ek[ 61] |= 32; ek[ 68] |= 16; ek[ 77] |=  8;
            ek[ 92] |=  1; ek[102] |=  4; ek[108] |=  8;
            ek[126] |= 16;
        }
        octet = key[3];
        if ((octet & 128) != 0) {
            ek[  2] |=  8; ek[  9] |=  1; ek[ 16] |= 16;
            ek[ 27] |=  4; ek[ 42] |=  1; ek[ 49] |= 16;
            ek[ 58] |=  2; ek[ 75] |=  1; ek[ 80] |=  1;
            ek[ 90] |=  4; ek[ 97] |= 32; ek[106] |= 32;
            ek[113] |=  8; ek[120] |= 32;
        }
        if ((octet & 64) != 0) {
            ek[  2] |=  4; ek[  8] |=  4; ek[ 27] |=  2;
            ek[ 32] |= 32; ek[ 41] |=  1; ek[ 48] |= 16;
            ek[ 59] |=  4; ek[ 66] |= 16; ek[ 72] |=  8;
            ek[ 91] |=  8; ek[107] |=  1; ek[112] |=  1;
            ek[123] |= 16;
        }
        if ((octet & 32) != 0) {
            ek[  3] |=  8; ek[ 10] |=  2; ek[ 16] |=  2;
            ek[ 25] |=  4; ek[ 35] |= 16; ek[ 40] |=  4;
            ek[ 59] |=  2; ek[ 65] |=  8; ek[ 74] |=  8;
            ek[ 83] |= 32; ek[ 89] |=  2; ek[ 98] |= 16;
            ek[104] |=  8; ek[121] |= 16;
        }
        if ((octet & 16) != 0) {
            ek[  4] |=  2; ek[ 13] |=  4; ek[ 22] |=  2;
            ek[ 28] |= 16; ek[ 37] |=  8; ek[ 52] |=  1;
            ek[ 62] |=  4; ek[ 79] |=  8; ek[ 86] |= 16;
            ek[ 95] |= 32; ek[101] |=  1; ek[110] |=  8;
            ek[126] |= 32;
        }
        if ((octet & 8) != 0) {
            ek[  5] |= 32; ek[ 12] |= 16; ek[ 21] |=  8;
            ek[ 36] |=  1; ek[ 46] |=  4; ek[ 52] |=  8;
            ek[ 70] |= 16; ek[ 79] |= 32; ek[ 85] |=  1;
            ek[ 94] |=  8; ek[108] |=  2; ek[119] |=  4;
            ek[126] |=  2;
        }
        if ((octet & 4) != 0) {
            ek[  5] |=  2; ek[ 14] |=  4; ek[ 20] |=  8;
            ek[ 37] |= 16; ek[ 44] |=  4; ek[ 55] |= 16;
            ek[ 60] |= 32; ek[ 76] |=  2; ek[ 87] |=  4;
            ek[ 93] |= 32; ek[103] |=  1; ek[110] |=  1;
            ek[119] |=  2; ek[124] |=  1;
        }
        if ((octet & 2) != 0) {
            ek[  7] |= 32; ek[ 12] |=  4; ek[ 23] |= 16;
            ek[ 28] |= 32; ek[ 38] |= 32; ek[ 45] |=  4;
            ek[ 54] |=  2; ek[ 60] |= 16; ek[ 71] |=  1;
            ek[ 78] |=  1; ek[ 87] |=  2; ek[ 93] |=  2;
            ek[111] |=  8; ek[118] |= 16; ek[125] |= 16;
        }
        octet = key[4];
        if ((octet & 128) != 0) {
            ek[  1] |=  1; ek[ 11] |= 32; ek[ 17] |=  2;
            ek[ 26] |= 16; ek[ 32] |=  8; ek[ 51] |=  8;
            ek[ 64] |=  2; ek[ 73] |=  4; ek[ 83] |= 16;
            ek[ 88] |=  4; ek[107] |=  2; ek[112] |= 32;
            ek[122] |=  8;
        }
        if ((octet & 64) != 0) {
            ek[  0] |=  4; ek[  9] |= 32; ek[ 18] |= 32;
            ek[ 25] |=  8; ek[ 34] |=  8; ek[ 43] |= 32;
            ek[ 49] |=  2; ek[ 58] |= 16; ek[ 74] |=  1;
            ek[ 81] |= 16; ek[ 90] |=  2; ek[ 96] |=  2;
            ek[105] |=  4; ek[115] |= 16; ek[122] |=  4;
        }
        if ((octet & 32) != 0) {
            ek[  2] |=  2; ek[ 19] |=  1; ek[ 24] |=  1;
            ek[ 34] |=  4; ek[ 41] |= 32; ek[ 50] |= 32;
            ek[ 57] |=  8; ek[ 64] |= 32; ek[ 73] |=  1;
            ek[ 80] |= 16; ek[ 91] |=  4; ek[106] |=  1;
            ek[113] |= 16; ek[123] |=  8;
        }
        if ((octet & 16) != 0) {
            ek[  3] |=  4; ek[ 10] |= 16; ek[ 16] |=  8;
            ek[ 35] |=  8; ek[ 51] |=  1; ek[ 56] |=  1;
            ek[ 67] |= 16; ek[ 72] |=  4; ek[ 91] |=  2;
            ek[ 96] |= 32; ek[105] |=  1; ek[112] |= 16;
            ek[121] |=  2;
        }
        if ((octet & 8) != 0) {
            ek[  4] |= 16; ek[ 15] |=  1; ek[ 22] |=  1;
            ek[ 31] |=  2; ek[ 37] |=  2; ek[ 55] |=  8;
            ek[ 62] |= 16; ek[ 69] |= 16; ek[ 76] |=  4;
            ek[ 87] |= 16; ek[ 92] |= 32; ek[102] |= 32;
            ek[109] |=  4; ek[118] |=  2; ek[125] |= 32;
        }
        if ((octet & 4) != 0) {
            ek[  6] |=  4; ek[ 23] |=  8; ek[ 30] |= 16;
            ek[ 39] |= 32; ek[ 45] |=  1; ek[ 54] |=  8;
            ek[ 70] |= 32; ek[ 77] |=  4; ek[ 86] |=  2;
            ek[ 92] |= 16; ek[101] |=  8; ek[116] |=  1;
            ek[125] |=  2;
        }
        if ((octet & 2) != 0) {
            ek[  4] |=  4; ek[ 13] |=  1; ek[ 22] |=  8;
            ek[ 36] |=  2; ek[ 47] |=  4; ek[ 53] |= 32;
            ek[ 63] |=  1; ek[ 69] |=  8; ek[ 84] |=  1;
            ek[ 94] |=  4; ek[100] |=  8; ek[117] |= 16;
            ek[127] |= 32;
        }
        octet = key[5];
        if ((octet & 128) != 0) {
            ek[  3] |= 32; ek[  8] |= 16; ek[ 19] |=  4;
            ek[ 34] |=  1; ek[ 41] |= 16; ek[ 50] |=  2;
            ek[ 56] |=  2; ek[ 67] |=  1; ek[ 72] |=  1;
            ek[ 82] |=  4; ek[ 89] |= 32; ek[ 98] |= 32;
            ek[105] |=  8; ek[114] |=  8; ek[121] |=  1;
        }
        if ((octet & 64) != 0) {
            ek[  1] |= 32; ek[ 19] |=  2; ek[ 24] |= 32;
            ek[ 33] |=  1; ek[ 40] |= 16; ek[ 51] |=  4;
            ek[ 64] |=  8; ek[ 83] |=  8; ek[ 99] |=  1;
            ek[104] |=  1; ek[114] |=  4; ek[120] |=  4;
        }
        if ((octet & 32) != 0) {
            ek[  8] |=  2; ek[ 17] |=  4; ek[ 27] |= 16;
            ek[ 32] |=  4; ek[ 51] |=  2; ek[ 56] |= 32;
            ek[ 66] |=  8; ek[ 75] |= 32; ek[ 81] |=  2;
            ek[ 90] |= 16; ek[ 96] |=  8; ek[115] |=  8;
            ek[122] |=  2;
        }
        if ((octet & 16) != 0) {
            ek[  2] |= 16; ek[ 18] |=  1; ek[ 25] |= 16;
            ek[ 34] |=  2; ek[ 40] |=  2; ek[ 49] |=  4;
            ek[ 59] |= 16; ek[ 66] |=  4; ek[ 73] |= 32;
            ek[ 82] |= 32; ek[ 89] |=  8; ek[ 98] |=  8;
            ek[107] |= 32; ek[113] |=  2; ek[123] |=  4;
        }
        if ((octet & 8) != 0) {
            ek[  7] |=  1; ek[ 13] |=  8; ek[ 28] |=  1;
            ek[ 38] |=  4; ek[ 44] |=  8; ek[ 61] |= 16;
            ek[ 71] |= 32; ek[ 77] |=  1; ek[ 86] |=  8;
            ek[100] |=  2; ek[111] |=  4; ek[117] |= 32;
            ek[124] |= 16;
        }
        if ((octet & 4) != 0) {
            ek[ 12] |=  8; ek[ 29] |= 16; ek[ 36] |=  4;
            ek[ 47] |= 16; ek[ 52] |= 32; ek[ 62] |= 32;
            ek[ 68] |=  2; ek[ 79] |=  4; ek[ 85] |= 32;
            ek[ 95] |=  1; ek[102] |=  1; ek[111] |=  2;
            ek[117] |=  2; ek[126] |=  4;
        }
        if ((octet & 2) != 0) {
            ek[  5] |=  1; ek[ 15] |= 16; ek[ 20] |= 32;
            ek[ 30] |= 32; ek[ 37] |=  4; ek[ 46] |=  2;
            ek[ 52] |= 16; ek[ 61] |=  8; ek[ 70] |=  1;
            ek[ 79] |=  2; ek[ 85] |=  2; ek[103] |=  8;
            ek[110] |= 16; ek[119] |= 32; ek[124] |=  4;
        }
        octet = key[6];
        if ((octet & 128) != 0) {
            ek[  0] |= 16; ek[  9] |=  2; ek[ 18] |= 16;
            ek[ 24] |=  8; ek[ 43] |=  8; ek[ 59] |=  1;
            ek[ 65] |=  4; ek[ 75] |= 16; ek[ 80] |=  4;
            ek[ 99] |=  2; ek[104] |= 32; ek[113] |=  1;
            ek[123] |= 32;
        }
        if ((octet & 64) != 0) {
            ek[ 10] |= 32; ek[ 17] |=  8; ek[ 26] |=  8;
            ek[ 35] |= 32; ek[ 41] |=  2; ek[ 50] |= 16;
            ek[ 56] |=  8; ek[ 66] |=  1; ek[ 73] |= 16;
            ek[ 82] |=  2; ek[ 88] |=  2; ek[ 97] |=  4;
            ek[107] |= 16; ek[112] |=  4; ek[121] |= 32;
        }
        if ((octet & 32) != 0) {
            ek[  0] |=  2; ek[ 11] |=  1; ek[ 16] |=  1;
            ek[ 26] |=  4; ek[ 33] |= 32; ek[ 42] |= 32;
            ek[ 49] |=  8; ek[ 58] |=  8; ek[ 65] |=  1;
            ek[ 72] |= 16; ek[ 83] |=  4; ek[ 98] |=  1;
            ek[105] |= 16; ek[114] |=  2;
        }
        if ((octet & 16) != 0) {
            ek[  8] |=  8; ek[ 27] |=  8; ek[ 43] |=  1;
            ek[ 48] |=  1; ek[ 58] |=  4; ek[ 64] |=  4;
            ek[ 83] |=  2; ek[ 88] |= 32; ek[ 97] |=  1;
            ek[104] |= 16; ek[115] |=  4; ek[122] |= 16;
        }
        if ((octet & 8) != 0) {
            ek[  5] |=  8; ek[ 14] |=  1; ek[ 23] |=  2;
            ek[ 29] |=  2; ek[ 47] |=  8; ek[ 54] |= 16;
            ek[ 63] |= 32; ek[ 68] |=  4; ek[ 79] |= 16;
            ek[ 84] |= 32; ek[ 94] |= 32; ek[101] |=  4;
            ek[110] |=  2; ek[116] |= 16; ek[127] |=  1;
        }
        if ((octet & 4) != 0) {
            ek[  4] |=  8; ek[ 15] |=  8; ek[ 22] |= 16;
            ek[ 31] |= 32; ek[ 37] |=  1; ek[ 46] |=  8;
            ek[ 60] |=  2; ek[ 69] |=  4; ek[ 78] |=  2;
            ek[ 84] |= 16; ek[ 93] |=  8; ek[108] |=  1;
            ek[118] |=  4;
        }
        if ((octet & 2) != 0) {
            ek[  7] |= 16; ek[ 14] |=  8; ek[ 28] |=  2;
            ek[ 39] |=  4; ek[ 45] |= 32; ek[ 55] |=  1;
            ek[ 62] |=  1; ek[ 76] |=  1; ek[ 86] |=  4;
            ek[ 92] |=  8; ek[109] |= 16; ek[116] |=  4;
            ek[125] |=  1;
        }
        octet = key[7];
        if ((octet & 128) != 0) {
            ek[  1] |=  2; ek[ 11] |=  4; ek[ 26] |=  1;
            ek[ 33] |= 16; ek[ 42] |=  2; ek[ 48] |=  2;
            ek[ 57] |=  4; ek[ 64] |=  1; ek[ 74] |=  4;
            ek[ 81] |= 32; ek[ 90] |= 32; ek[ 97] |=  8;
            ek[106] |=  8; ek[115] |= 32; ek[120] |= 16;
        }
        if ((octet & 64) != 0) {
            ek[  2] |= 32; ek[ 11] |=  2; ek[ 16] |= 32;
            ek[ 25] |=  1; ek[ 32] |= 16; ek[ 43] |=  4;
            ek[ 58] |=  1; ek[ 75] |=  8; ek[ 91] |=  1;
            ek[ 96] |=  1; ek[106] |=  4; ek[113] |= 32;
        }
        if ((octet & 32) != 0) {
            ek[  3] |=  1; ek[  9] |=  4; ek[ 19] |= 16;
            ek[ 24] |=  4; ek[ 43] |=  2; ek[ 48] |= 32;
            ek[ 57] |=  1; ek[ 67] |= 32; ek[ 73] |=  2;
            ek[ 82] |= 16; ek[ 88] |=  8; ek[107] |=  8;
            ek[120] |=  2;
        }
        if ((octet & 16) != 0) {
            ek[  0] |=  8; ek[ 10] |=  1; ek[ 17] |= 16;
            ek[ 26] |=  2; ek[ 32] |=  2; ek[ 41] |=  4;
            ek[ 51] |= 16; ek[ 56] |=  4; ek[ 65] |= 32;
            ek[ 74] |= 32; ek[ 81] |=  8; ek[ 90] |=  8;
            ek[ 99] |= 32; ek[105] |=  2; ek[114] |= 16;
        }
        if ((octet & 8) != 0) {
            ek[  6] |=  1; ek[ 20] |=  1; ek[ 30] |=  4;
            ek[ 36] |=  8; ek[ 53] |= 16; ek[ 60] |=  4;
            ek[ 69] |=  1; ek[ 78] |=  8; ek[ 92] |=  2;
            ek[103] |=  4; ek[109] |= 32; ek[119] |=  1;
            ek[125] |=  8;
        }
        if ((octet & 4) != 0) {
            ek[  7] |=  8; ek[ 21] |= 16; ek[ 28] |=  4;
            ek[ 39] |= 16; ek[ 44] |= 32; ek[ 54] |= 32;
            ek[ 61] |=  4; ek[ 71] |=  4; ek[ 77] |= 32;
            ek[ 87] |=  1; ek[ 94] |=  1; ek[103] |=  2;
            ek[109] |=  2; ek[124] |=  8;
        }
        if ((octet & 2) != 0) {
            ek[  6] |=  8; ek[ 12] |= 32; ek[ 22] |= 32;
            ek[ 29] |=  4; ek[ 38] |=  2; ek[ 44] |= 16;
            ek[ 53] |=  8; ek[ 71] |=  2; ek[ 77] |=  2;
            ek[ 95] |=  8; ek[102] |= 16; ek[111] |= 32;
            ek[117] |=  1; ek[127] |= 16;
        }

        expandedKey = ek;       
    }
}