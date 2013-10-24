/*
 * This class was taken from the open source GNU Crypto project and modified to work 
 * in apex.
 * 
 * @author Nate Wallace
 */

// ----------------------------------------------------------------------------
// $Id: MD4.java,v 1.5 2002/12/08 00:26:55 rsdio Exp $
//
// Copyright (C) 2001, 2002, Free Software Foundation, Inc.
//
// This file is part of GNU Crypto.
//
// GNU Crypto is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//
// GNU Crypto is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to the
//
//    Free Software Foundation Inc.,
//    59 Temple Place - Suite 330,
//    Boston, MA 02111-1307
//    USA
//
// Linking this library statically or dynamically with other modules is
// making a combined work based on this library.  Thus, the terms and
// conditions of the GNU General Public License cover the whole
// combination.
//
// As a special exception, the copyright holders of this library give
// you permission to link this library with independent modules to
// produce an executable, regardless of the license terms of these
// independent modules, and to copy and distribute the resulting
// executable under terms of your choice, provided that you also meet,
// for each linked independent module, the terms and conditions of the
// license of that module.  An independent module is a module which is
// not derived from or based on this library.  If you modify this
// library, you may extend this exception to your version of the
// library, but you are not obligated to do so.  If you do not wish to
// do so, delete this exception statement from your version.
// ----------------------------------------------------------------------------

/**
 * <p>An implementation of Ron Rivest's MD4 message digest algorithm.</p>
 *
 * <p>MD4 was the precursor to the stronger {@link gnu.crypto.hash.MD5}
 * algorithm, and while not considered cryptograpically secure itself, MD4 is
 * in use in various applications. It is slightly faster than MD5.</p>
 *
 * <p>References:</p>
 *
 * <ol>
 *    <li>The <a href="http://www.ietf.org/rfc/rfc1320.txt">MD4</a>
 *    Message-Digest Algorithm.<br>
 *    R. Rivest.</li>
 * </ol>
 *
 * @version $Revision: 1.5 $
 * @author Casey Marshall (rsdio@metastatic.org)
 */
public class MD4Hash {

    // Constants and variables
    // -------------------------------------------------------------------------

    /** An MD4 message digest is always 128-bits long, or 16 bytes. */
    private static final integer DIGEST_LENGTH = 16;

    /** The MD4 algorithm operates on 512-bit blocks, or 64 bytes. */
    private static final integer BLOCK_LENGTH = 64;

    /** Holds variable values used in the MD4 calculation. **/
    private integer a, b, c, d;

    /** Number of bytes processed so far. */
    private long count;

    /** Temporary input buffer. */
    private integer[] buffer;   

    // Constructor(s)
    // -------------------------------------------------------------------------

    /**
    * <p>Public constructor. Initializes the chaining variables, sets the byte
    * count to <code>0</code>, and creates a new block of <code>512</code> bits.
    * </p>
    */
    public MD4Hash() {
        this.buffer = new integer[BLOCK_LENGTH];
        reset();
        resetContext();
    }

    // Instance methods
    // -------------------------------------------------------------------------

    /*
     * Create an MD4 digest from the given input.
     *
     * @param input The data to create an MD4 digest for.
     * @return The MD4 digest created from the input data.
     */
    public integer[] digest(integer[] input) {
        updateBuffer(input, 0, input.size());
        return digest();
    }

    /*
     * Helper function used to copy data from one array to another.
     *
     * @param src The array to copy data from.
     * @param srcPos The position in the source array to start copying data from.
     * @param dest The array to copy data to.
     * @param destPos The position in the destination array to start copying data to.
     * @param length The number of bytes to copy from the source array to the destination array.
     */
    private static void arrayCopy(integer[] src, integer srcPos, integer[] dest, integer destPos, integer length) {
        for (integer i = 0; i < length; i++)
            dest[destPos + i] = src[srcPos + i];
    }

    /*
     * Update the buffer that holds the data the MD4 digest will be created from.
     *
     * @param b The data to update the buffer with.
     * @param offset The offset in b to start reading the data from.
     * @param len The amount of data to read from b.
     */
    private void updateBuffer(integer[] b, integer offset, integer len) {
        integer n = (integer)(Math.mod(count, BLOCK_LENGTH));
        count += len;
        integer partLen = BLOCK_LENGTH - n;
        integer i = 0;

        if (len >= partLen) {
            arraycopy(b, offset, buffer, n, partLen);
            transform(buffer, 0);
            for (i = partLen; i + BLOCK_LENGTH - 1 < len; i+= BLOCK_LENGTH) {
                transform(b, offset + i);
            }
            n = 0;
        }

        if (i < len) {
            arraycopy(b, offset + i, buffer, n, len - i);
        }
    }

    /*
     * Create MD4 digest from the data currently in the buffer and then reset this object for any future re-use.
     *
     * @return The MD4 digest created from the data in the buffer.
     */
    private integer[] digest() {
        integer[] tail = padBuffer(); // pad remaining bytes in buffer
        updateBuffer(tail, 0, tail.size()); // last transform of a message
        integer[] result = getResult(); // make a result out of context

        reset(); // reset this instance for future re-use

        return result;
    }

    /*
     * Rest all object members to their initial values.
     */
    private void reset() { // reset this instance for future re-use
        count = 0;
        for (integer i = 0; i < BLOCK_LENGTH; ) {
            buffer[i++] = 0;
        }

        resetContext();
    }

    // Implementation of abstract methods in BashHash --------------------------

    /*
     * Computes the result of the MD4 operation.
     *
     * @return The MD4 result.
     */
    private integer[] getResult() {
        integer[] digest = new integer[] {
         (a & 255), ((a >>> 8) & 255), ((a >>> 16) & 255), ((a >>> 24) & 255),
         (b & 255), ((b >>> 8) & 255), ((b >>> 16) & 255), ((b >>> 24) & 255),
         (c & 255), ((c >>> 8) & 255), ((c >>> 16) & 255), ((c >>> 24) & 255),
         (d & 255), ((d >>> 8) & 255), ((d >>> 16) & 255), ((d >>> 24) & 255)
        };
        
        return digest;
    }

    /*
     * Reset a, b, c, d to their initial values.
     */
    private void resetContext() {
        a = 1732584193; 
        b = -271733879;
        c = -1732584194; 
        d = 271733878;
    }

    /*
     * Get padding needed for the buffer.
     *
     * @return padding needed for the buffer.
     */
    private integer[] padBuffer() {
        integer n = (integer) (Math.mod(count, BLOCK_LENGTH));
        integer padding = (n < 56) ? (56 - n) : (120 - n);     
        integer[] pad = new integer[padding + 8];
        for (integer i = 0; i < pad.size(); i++)
            pad[i] = 0;

        pad[0] = 128;
        long bits = count << 3;
        pad[padding++] = (integer)(bits & 255);
        pad[padding++] = (integer)((bits >>>  8) & 255);
        pad[padding++] = (integer)((bits >>> 16) & 255);
        pad[padding++] = (integer)((bits >>> 24) & 255);
        pad[padding++] = (integer)((bits >>> 32) & 255);
        pad[padding++] = (integer)((bits >>> 40) & 255);
        pad[padding++] = (integer)((bits >>> 48) & 255);
        pad[padding  ] = (integer)((bits >>> 56) & 255);

        return pad;
    }

    /*
     * Perform the MD4 transform operation.
     *
     * @param input The data to transform.
     * @param i The offset in data to start the transform operation at.
     */
    private void transform(integer[] input, integer i) {
       
        integer X0 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);      
        integer X1 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X2 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X3 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X4 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X5 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X6 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X7 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X8 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X9 =  ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X10 = ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X11 = ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X12 = ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X13 = ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X14 = ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i++] << 24);
        integer X15 = ((((input[i++] & 255) | (input[i++] & 255) << 8) | (input[i++] & 255) << 16) | input[i  ] << 24);    

        integer aa, bb, cc, dd;

        aa = a;  bb = b;  cc = c;  dd = d;

        aa += ((bb & cc) | ((BitConverter.getIntegerComplement(bb)) & dd)) + X0;   
        aa = aa <<  3 | aa >>> -3;         
        dd += ((aa & bb) | ((BitConverter.getIntegerComplement(aa)) & cc)) + X1;        
        dd = dd <<  7 | dd >>> -7;
        cc += ((dd & aa) | ((BitConverter.getIntegerComplement(dd)) & bb)) + X2;
        cc = cc << 11 | cc >>> -11;
        bb += ((cc & dd) | ((BitConverter.getIntegerComplement(cc)) & aa)) + X3;
        bb = bb << 19 | bb >>> -19;
        aa += ((bb & cc) | ((BitConverter.getIntegerComplement(bb)) & dd)) + X4;
        aa = aa <<  3 | aa >>> -3;  
        dd += ((aa & bb) | ((BitConverter.getIntegerComplement(aa)) & cc)) + X5;
        dd = dd <<  7 | dd >>> -7;
        cc += ((dd & aa) | ((BitConverter.getIntegerComplement(dd)) & bb)) + X6;
        cc = cc << 11 | cc >>> -11;
        bb += ((cc & dd) | ((BitConverter.getIntegerComplement(cc)) & aa)) + X7;
        bb = bb << 19 | bb >>> -19;
        aa += ((bb & cc) | ((BitConverter.getIntegerComplement(bb)) & dd)) + X8;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa & bb) | ((BitConverter.getIntegerComplement(aa)) & cc)) + X9;
        dd = dd <<  7 | dd >>> -7;
        cc += ((dd & aa) | ((BitConverter.getIntegerComplement(dd)) & bb)) + X10;
        cc = cc << 11 | cc >>> -11;
        bb += ((cc & dd) | ((BitConverter.getIntegerComplement(cc)) & aa)) + X11;
        bb = bb << 19 | bb >>> -19;
        aa += ((bb & cc) | ((BitConverter.getIntegerComplement(bb)) & dd)) + X12;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa & bb) | ((BitConverter.getIntegerComplement(aa)) & cc)) + X13;
        dd = dd <<  7 | dd >>> -7;
        cc += ((dd & aa) | ((BitConverter.getIntegerComplement(dd)) & bb)) + X14;
        cc = cc << 11 | cc >>> -11;
        bb += ((cc & dd) | ((BitConverter.getIntegerComplement(cc)) & aa)) + X15;
        bb = bb << 19 | bb >>> -19;

        aa += ((bb & (cc | dd)) | (cc & dd)) + X0 + 1518500249;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa & (bb | cc)) | (bb & cc)) + X4 + 1518500249;
        dd = dd <<  5 | dd >>> -5;
        cc += ((dd & (aa | bb)) | (aa & bb)) + X8 + 1518500249;
        cc = cc <<  9 | cc >>> -9;
        bb += ((cc & (dd | aa)) | (dd & aa)) + X12 + 1518500249;
        bb = bb << 13 | bb >>> -13;
        aa += ((bb & (cc | dd)) | (cc & dd)) + X1 + 1518500249;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa & (bb | cc)) | (bb & cc)) + X5 + 1518500249;
        dd = dd <<  5 | dd >>> -5;
        cc += ((dd & (aa | bb)) | (aa & bb)) + X9 + 1518500249;
        cc = cc <<  9 | cc >>> -9;
        bb += ((cc & (dd | aa)) | (dd & aa)) + X13 + 1518500249;
        bb = bb << 13 | bb >>> -13;
        aa += ((bb & (cc | dd)) | (cc & dd)) + X2 + 1518500249;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa & (bb | cc)) | (bb & cc)) + X6 + 1518500249;
        dd = dd <<  5 | dd >>> -5;
        cc += ((dd & (aa | bb)) | (aa & bb)) + X10 + 1518500249;
        cc = cc <<  9 | cc >>> -9;
        bb += ((cc & (dd | aa)) | (dd & aa)) + X14 + 1518500249;
        bb = bb << 13 | bb >>> -13;
        aa += ((bb & (cc | dd)) | (cc & dd)) + X3 + 1518500249;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa & (bb | cc)) | (bb & cc)) + X7 + 1518500249;
        dd = dd <<  5 | dd >>> -5;
        cc += ((dd & (aa | bb)) | (aa & bb)) + X11 + 1518500249;
        cc = cc <<  9 | cc >>> -9;
        bb += ((cc & (dd | aa)) | (dd & aa)) + X15 + 1518500249;
        bb = bb << 13 | bb >>> -13;

        aa += ((bb ^ cc) ^ dd) + X0 + 1859775393;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa ^ bb) ^ cc) + X8 + 1859775393;
        dd = dd <<  9 | dd >>> -9;
        cc += ((dd ^ aa) ^ bb) + X4 + 1859775393;
        cc = cc << 11 | cc >>> -11;
        bb += ((cc ^ dd) ^ aa) + X12 + 1859775393;
        bb = bb << 15 | bb >>> -15;
        aa += ((bb ^ cc) ^ dd) + X2 + 1859775393;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa ^ bb) ^ cc) + X10 + 1859775393;
        dd = dd <<  9 | dd >>> -9;
        cc += ((dd ^ aa) ^ bb) + X6 + 1859775393;
        cc = cc << 11 | cc >>> -11;
        bb += ((cc ^ dd) ^ aa) + X14 + 1859775393;
        bb = bb << 15 | bb >>> -15;
        aa += ((bb ^ cc) ^ dd) + X1 + 1859775393;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa ^ bb) ^ cc) + X9 + 1859775393;
        dd = dd <<  9 | dd >>> -9;
        cc += ((dd ^ aa) ^ bb) + X5 + 1859775393;
        cc = cc << 11 | cc >>> -11;
        bb += ((cc ^ dd) ^ aa) + X13 + 1859775393;
        bb = bb << 15 | bb >>> -15;
        aa += ((bb ^ cc) ^ dd) + X3 + 1859775393;
        aa = aa <<  3 | aa >>> -3;
        dd += ((aa ^ bb) ^ cc) + X11 + 1859775393;
        dd = dd <<  9 | dd >>> -9;
        cc += ((dd ^ aa) ^ bb) + X7 + 1859775393;
        cc = cc << 11 | cc >>> -11;
        bb += ((cc ^ dd) ^ aa) + X15 + 1859775393;
        bb = bb << 15 | bb >>> -15;

        a += aa; b += bb; c += cc; d += dd;      
    }
}