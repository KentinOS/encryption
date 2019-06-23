package encryption.impl.bigInteger;

import encryption.Encryptible;

import java.util.Arrays;
import java.util.Random;

public class BigInteger extends java.math.BigInteger implements Encryptible<BigInteger> {

    public static final BigInteger ONE = new BigInteger(java.math.BigInteger.ONE);
    public static final BigInteger ZERO = new BigInteger(java.math.BigInteger.ZERO);

    public BigInteger(byte[] val) {
        super(val);
    }

    public BigInteger(int signum, byte[] magnitude) {
        super(signum, magnitude);
    }

    public BigInteger(String val, int radix) {
        super(val, radix);
    }

    public BigInteger(String val) {
        super(val);
    }

    public BigInteger(int numBits, Random rnd) {
        super(numBits, rnd);
    }

    public BigInteger(int bitLength, int certainty, Random rnd) {
        super(bitLength, certainty, rnd);
    }

    public BigInteger(java.math.BigInteger bigInteger) {
        this(bigInteger.toByteArray());
    }

    @Override
    public BigInteger xor(BigInteger val) {
        return new BigInteger(super.xor(val));
    }

    @Override
    public BigInteger leftShift(int n, boolean isLoop) {
        if (n < 0) {
            throw new IllegalArgumentException("n is invalid");
        }
        BigInteger thisOne = new BigInteger(this);
        if (n == 0) {
            return thisOne;
        }
        final java.math.BigInteger bigInteger = new java.math.BigInteger(thisOne.toString(2).substring(0, n), 2);
        java.math.BigInteger shiftLeft = thisOne.shiftLeft(n);
        if (isLoop) {
            shiftLeft = shiftLeft.or(bigInteger);
        }
        return new BigInteger(shiftLeft);
    }

    public BigInteger subtract(BigInteger val) {
        return new BigInteger(super.subtract(val));
    }

    public BigInteger multiply(BigInteger val) {
        return new BigInteger(super.multiply(val));
    }

    public BigInteger divide(BigInteger val) {
        return new BigInteger(super.divide(val));
    }

    public BigInteger modPow(BigInteger exponent, BigInteger m) {
        return new BigInteger(super.modPow(exponent, m));
    }

    public BigInteger add(BigInteger val) {
        return new BigInteger(super.add(val));
    }

    //父子静态方法并无任何关系，单纯是重名方法,静态方法会分析整个字节码文件，刚刚报的NPE真正原因在于其他本字节码文件静态方法调用存在npe异常
    public static BigInteger probablePrime(int bitLength, Random random) {
        java.math.BigInteger probablePrime = java.math.BigInteger.probablePrime(bitLength, random);
        return new BigInteger(probablePrime);
    }


    public BigInteger gcd(BigInteger val) {
        return new BigInteger(super.gcd(val));
    }

    public BigInteger mod(BigInteger m) {
        return new BigInteger(super.mod(m));
    }

    public BigInteger remainder(BigInteger val) {
        return new BigInteger(super.remainder(val));
    }

    @Override
    public BigInteger negate() {
        return new BigInteger(super.negate());
    }

    @Override
    public BigInteger nextProbablePrime() {
        return new BigInteger(super.nextProbablePrime());
    }

    /**
     * 扩展方法
     */


    /**
     * 字符串<->大整数
     */
    /**
     * 用于明文字符串转换成大整数，需要数值小于模，
     * 返回unicode编码标准的字符串对应的数串作为的大整数串
     *
     * @param charStr
     * @return
     */
    public static BigInteger valueOfString(String charStr) {
        if (charStr == null) {
            throw new NullPointerException("string data is null!");
        }


        char[] chars = charStr.toCharArray();
        final int length = chars.length;
        StringBuilder res = new StringBuilder();
        final char mask = 0x0001;
        final int uBitSize = Character.SIZE;

        for (int i = 0; i < length; i++) {
            char work = chars[i];
            for (int j = uBitSize - 1; j >= 0; j--) {
                res.append((work >> j) & mask);
            }
        }
//注意以下构造后前导0被抹掉，以下序列化还原的方法会加回去，用加前导“1”防止抹掉不可取，因为bigInteger不只是能用当前方法构造，其他bigInteger就不能调用这对方法了
        return new BigInteger(res.toString(), 2);
    }

    /**
     * 大整数转换成unicode编码的字符串，由于大素数作模的处理使数串可以超过1024bit，足以直接作为返回串,然而为作进一步加密，采用unicode标准。
     *
     * @return
     */
    public String stringOfValue() {
        //取数串
        String binString = this.toString(2);
        /**
         * 19-5-3 曾经因为历史代码没修改过来这里隐藏了bug ， 最终耗了好久， 希望能长记性了！
         * 历史版本的实现是采用了在第一位加前导1保留前导0的暴力解决方法，如今纠正过来，但之前的旧代码只部分更正了，导致自认为诡异的bug
         * bug表现为：虽然有正确解密的次数，但居然还会出现较大频率的错误解密，甚至这导致我怀疑起之前苦心孤诣的RSA算法的可靠性，最后还是测试出来的
         * 建议：多尝试善学善用新的高效debug工具
         */
//        if ((binChars.length - 1) % Character.SIZE != 0) {
//            throw new IllegalArgumentException("invalid binChars");
//        }
        final int usize = Character.SIZE;
        final int remainder = binString.length() % usize;
        if (remainder > 0) {
            final char[] tmpChars = new char[usize - remainder];
            Arrays.fill(tmpChars, '0');
            binString = new String(tmpChars).concat(binString);
        }
        final char[] binChars = binString.toCharArray();
        //结果容器
        final StringBuilder res = new StringBuilder();
        //按每两字节(对应01串的16字符)取一字符
        final char mask = 0x0001;
        final int bitSize = 1;
        final int groupLength = binChars.length / usize;
        for (int i = 0; i < groupLength; i++) {
            char work = 0;
            for (int j = 0; j < usize; j++) {
                work <<= bitSize;
                work |= (binChars[i * usize + j] & mask);
            }
            res.append(work);
        }
        return res.toString();
    }

}
