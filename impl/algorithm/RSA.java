package encryption.impl.algorithm;

import encryption.impl.BlockPassword;
import encryption.impl.bigInteger.BigInteger;

import java.util.Random;
import java.util.Stack;

/**
 * RSA
 * 非对称加密（又称公钥加密）
 * 该体系无统一的密码结构
 * 1.非对称的加密特征使之可允许加密解密的算法步骤不成对称，
 * 加密可以比解密更复杂。
 * 2.该体系聚焦在安全的加密算法而非密码结构，
 * 故焦点在于加密的关于数论的抗击
 */
@SuppressWarnings("JavaDoc")
public class RSA extends BlockPassword<BigInteger> {

    /**
     * 二进制计算
     * 按比特位计算大小
     */

    private static final int N_BIT_LENGTH_LOWER_BOUND = ASYMMETRIC_BIT;


    private static final int MAX_TIMES_BOUND = 2;
    /**
     * 较大素数的比特长度
     */
    private static final int BIT_LENGTH = N_BIT_LENGTH_LOWER_BOUND * (random.nextInt(MAX_TIMES_BOUND) + 2);
    /**
     * 小素数
     */
    private final int subBitLength = BIT_LENGTH / 2;

    /**
     * BigInteger包下的配置性变量定义
     */
    private int defaultCertainty = 100;

    /*
      RSA 由三位作者的名字首字母组成的命名
      块加密 ， 将明文分块加密，块大小与以下特化密切相关
      关键值：
      均为大数：
      n , p , q ,
      e , d
      前置条件： 明文m 远小于 n , 1 < d < k
      特化：为更好地实现该加密算法，具体化以下取值以及规则：
      公钥：（e , n）
      私钥：（d , n）
      取值：
      1. c = m ^ e % n
      2. m = c ^ d % n
      3. d = e ^ (f(n) - 1) (弃用该取值)
      基本性质：
      1.n的取值要比明文分组的整型值（可取512bit = 64byte）都大（故可取512bit的质数）
         n = p * q  （p、q质数） :
         1）找正质数p , q
      则设有欧拉函数k = f(n) = (p - 1) * (q - 1),
       2. e * d = 1 (mod k) ：
         2）随机生成(1 , k) 内的正质数d
         3）d = e ^ (f(n) - 1)
       3. 公钥(e , n) , 私钥(d , n)
         4) 密文c = m ^ e % n
         5) 明文m = c ^ d % n
     */

    /**
     * 之所以找寻p,q而不是给出n找p,q
     * 是因为p,q带有更为明显的数值特征（正质数）,
     * 而n只是p,q之乘积（这样的数找出来难度更大，
     * 需要确保n因子分解出来有且仅有两个质因数）
     */


    private final BigInteger n;
    private final BigInteger k;

    private BigInteger e;
    private BigInteger d;

    /**
     * 首次生成密钥
     */
    private RSA() {
        super(BIT_LENGTH / 4);
        //p , q必须要比明文长度大 ， 故subLength是明文可加密的最大长度
        int randBitLength = this.subBitLength + new Random().nextInt(32);
        //p , q为达到k与(e或d)互质的效果，最好不要分别生成
        BigInteger p = this.randomPrimeNumber(randBitLength);
        BigInteger q = this.randomPrimeNumber(randBitLength);

        this.n = p.multiply(q);
        this.k = this.eulerForPrimeNumber(p, q);

        this.generateKeys();

//        System.out.println("首次生成RSA密钥");
    }

    /**
     * 获取该次加密中n的bit数
     *
     * @return
     */
    @Override
    protected int getBitLength() {
        return this.n.bitLength();
    }

    @Override
    public BigInteger convertString(String text) {
        if (text == null) {
            throw new NullPointerException("text is null");
        }
        return BigInteger.valueOfString(text);
    }

    @Override
    public String recoverString(BigInteger obj) {
        if (obj == null) {
            throw new NullPointerException("obj is null");
        }
        return obj.stringOfValue();
    }

    private static RSA rsa;

    public static RSA getInstance() {
        if (rsa == null) {
            rsa = new RSA();
        }
        return rsa;
    }

    /**
     * 加密
     *
     * @param msg
     * @return
     */
    @Override
    public BigInteger encrypt(BigInteger msg, BigInteger publicKey) {
        return this.getResultOfModN(msg, publicKey);
    }

    /**
     * 解密
     *
     * @param pwd
     * @return
     */
    @Override
    public BigInteger decrypt(BigInteger pwd, BigInteger privateKey) {
        return this.getResultOfModN(pwd, privateKey);
    }

    /*
      为抽离并独立实现，所有运算操作不用lambda表达式 ，
      而是私有方法实现

      大数运算，目前尤其棘手：

      1.指数为大数的运算(E/32分解法) （弃用，时间开销大，考虑到上述特化取值3弃用后只有加密解密处用到pow且均取模故直接使用标准包方法）

      2.随机生成一定的素数而非可能的素数(根源：确定性与时间开销的矛盾)
      （然而至今并不存在在有限的时间开销下生成一定的大素数的通性通法，
      该实现虽有风险但也是概率很低的风险，很大程度上逼近确定性算法，
      只能生成可能素数的根本原因是通过素数测试是素数的必要条件，但非充分条件）

      3.分解运算的难度在于如何正确然后又如何优化 （有待提高）
     */

    // 19-4-25 加油！

    /**
     * 计算公式 a = b ^ c % N
     *
     * @param bigInteger
     * @param key
     * @return
     */
    private BigInteger getResultOfModN(BigInteger bigInteger, BigInteger key) {
        return bigInteger.modPow(key, this.n);
    }

    /**
     * 生成随机素数 , 在源码中有说明 ： 返回值超过(1 - 1/2^100) = 99.99%的概率是素数 , 可认为是确定性算法
     *
     * @param bitLength
     * @return
     */
    private BigInteger randomPrimeNumber(int bitLength) {
        BigInteger bigInteger = BigInteger.probablePrime(bitLength, new Random());
        return this.getInvalidBigInteger(bigInteger);
    }

    private BigInteger getInvalidBigInteger(BigInteger bigInteger) {
        BigInteger res = bigInteger;
        String bStr = res.toString();
        char bVal = bStr.charAt(bStr.length() - 1);
        /*
          由于5为公钥，p-1 , q-1均不能为以0为末尾的大数
         */
        while (bVal == '1') {
            res = res.nextProbablePrime();
            bStr = res.toString();
            bVal = bStr.charAt(bStr.length() - 1);
        }
        return res;
    }

    /**
     * s = kt + 1 => s (k + 1) = (kt + 1) (k + 1) = kt(k + 1) + k + 1 = k[t(k + 1) + 1] + 1 = kt' + 1
     * 以上推理相当科学合理 ，然而是错用在此处
     * 大胆猜测的是：当d , e 都大于 k 时加密会无效即 m = m ^e % n. ： 已经过有限枚举证实
     * 当 d , e 不都大于 k 时 加密可行!
     * 遗憾的是，e不能太大的，否则加密会慢，所以在可以选择小数的时候不该采用K*prime - 1;
     *
     * @return
     */
    @Deprecated
    private void generateKeysDeprecated() {
//        密钥对 ， 私钥和公钥
        /*
          可以不是素数
         */
        final BigInteger probablePrime = BigInteger.probablePrime(2, new Random());
        final BigInteger factor1 = this.k.multiply(probablePrime).subtract(BigInteger.ONE);
//        必须为 k-1 , 因为要满足1 < x < k 且 与 k 互质
        final BigInteger factor2 = this.k.subtract(BigInteger.ONE);
        this.d = factor1;
        this.e = factor2;
    }

    private void generateKeys() {
        this.e = new BigInteger("5");
        System.out.println(this.k);
        final Stack<BigInteger> integerStack = this.euclid(this.e, this.k);
        int size = integerStack.size();

        //ed - kt = 1
        BigInteger res = BigInteger.ONE;
//        偶数 , t = ed - 1
        if ((size & 0x00000001) == 0x0000000) {
            integerStack.push(res);
        }

        BigInteger offset = BigInteger.ONE.negate();
        BigInteger b, s = integerStack.pop();
        while (!integerStack.empty()) {
            b = integerStack.peek();
            res = res.multiply(b).add(offset).divide(s);
            s = integerStack.pop();
            offset = offset.negate();
        }
        this.d = res;
    }

    /**
     * @param divider
     * @param dividend
     * @return
     */
    private Stack<BigInteger> euclid(BigInteger divider, BigInteger dividend) {
        final Stack<BigInteger> stack = new Stack<>();
        stack.push(dividend);
        stack.push(divider);
        BigInteger remainder = dividend.remainder(divider);
        while (remainder.compareTo(BigInteger.ONE) != 0) {
            stack.push(remainder);
            dividend = divider;
            divider = remainder;
            remainder = dividend.remainder(divider);
        }
        return stack;
    }

    /**
     * 关于大素数积n的欧拉函数
     *
     * @param primePositive1
     * @param primePositive2
     * @return
     */
    private BigInteger eulerForPrimeNumber(BigInteger primePositive1, BigInteger primePositive2) {
        return primePositive1.subtract(BigInteger.ONE).multiply(primePositive2.subtract(BigInteger.ONE));
    }

    /**
     * 获取公钥，对外提供接口
     *
     * @return
     */
    public String getPublicKeyOfN() {
        return this.n.toString();
    }

    /**
     * 获取公钥，对外提供接口
     *
     * @return
     */
    public String getPublicKeyOfE(String n) {
        if (n == null) {
            throw new NullPointerException("n is null");
        }
        if (!n.equals(this.n.toString())) {
            return null;
        }
        return this.e.toString();
    }

    /**
     * 获取私钥，对外只提供给服务器端
     *
     * @return
     */
    public String getPrivateKey(String e, String n) {
        if (e == null) {
            throw new NullPointerException("e is null");
        }
        if (n == null) {
            throw new NullPointerException("n is null");
        }
        if (
                !n.equals(this.n.toString())
                        || !e.equals(this.e.toString())
        ) {
            return null;
        }
        return this.d.toString();
    }

    /*
      须注意加解密都不用编码序列化的方法（如convertString , recoverString ， 即字符串<->整数的方法）
      直接返回this.toString（即BigInteger.toString）,即都是数串<->整数
     */

    /**
     * 对外加密接口（应用CBC版本）
     *
     * @param msg
     * @param eStr
     * @param nStr
     * @return
     */
    public StringBuffer encrypt(StringBuffer msg, String eStr, String nStr) {
        if (!this.n.toString().equals(nStr)) {
            throw new IllegalArgumentException("提供的n与当前RSA的n不一致");
        }
        if (!this.e.toString().equals(eStr)) {
            throw new IllegalArgumentException("提供的e与当前RSA的e不一样");
        }
        final BigInteger e = new BigInteger(eStr);
        return this.encrypt_ECB_with_multiply_threads(msg, e);
    }

    /**
     * 对外解密接口（应用CBC版本）
     */
    public StringBuffer decrypt(StringBuffer pwd, String dStr, String nStr) {
        if (!this.n.toString().equals(nStr)) {
            throw new IllegalArgumentException("提供的n与当前RSA的n不一致");
        }
        final BigInteger d = new BigInteger(dStr);
        return this.decrypt_ECB_with_multiply_threads(pwd, d);
    }

    public static void main(String[] a) {
        final RSA rsa = RSA.getInstance();
        final BigInteger encrypt = rsa.encrypt(new BigInteger("213234"), rsa.e);
        final BigInteger decrypt = rsa.decrypt(encrypt, rsa.d);
        System.out.println(decrypt);
    }
}
