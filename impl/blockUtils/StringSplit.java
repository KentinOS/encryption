package encryption.impl.blockUtils;

public class StringSplit {
    //字符串分组
    private final static int DEFAULT_GROUP_BIT = Long.SIZE;
    private final int size;

    //消息处理区间指针
    private int start;
    private int end;

    //缓冲区
    private StringBuffer stringBuffer;

    //迭代子
    private String next;

    //是否填充
    private final boolean isPadding;

    /**
     * Constructor1
     *
     * @param stringBuffer
     * @param bitSize
     * @param uBitSize
     * @param isPadding
     */
    public StringSplit(StringBuffer stringBuffer, int bitSize, int uBitSize, boolean isPadding) {
        this(
                stringBuffer,
                (bitSize <= 0 ? 0 : bitSize - 1) / (uBitSize <= 0 ? Character.SIZE : uBitSize) + 1,
                isPadding
        );
    }

    /**
     * Constructor2
     *
     * @param stringBuffer
     * @param isPadding
     */
    public StringSplit(StringBuffer stringBuffer, boolean isPadding) {
        this(stringBuffer, DEFAULT_GROUP_BIT, 0, isPadding);
    }

    /**
     * Constructor3
     *
     * @param stringBuffer
     * @param size
     * @param isPadding
     */
    public StringSplit(StringBuffer stringBuffer, int size, boolean isPadding) {
        if (size <= 0) {
            throw new IllegalArgumentException("size <= 0");
        }
        this.stringBuffer = stringBuffer;
        this.size = size;
        this.start = 0;
        this.end = this.start + size;
        this.next = "";
        this.isPadding = isPadding;
    }

    /**
     * substring = string[start , end)
     *
     * @return
     */
    private String getSubString() {

        int size = this.stringBuffer.length();
        if (this.start >= size) {
            return null;
        }
        this.preDeal(size);
        String res = this.stringBuffer.substring(this.start, this.end);
        this.start = this.end;
        this.end = this.start + this.size;
        return res;
    }

    public static final char PADDING = '\0';

    private void preDeal(int length) {
        if (this.end > length) { //尾指针超出长度的处理
            if (this.isPadding) { //需要填充
                int tabSize = (this.end - length) % this.size;
                for (int i = 0; i < tabSize; i++) {
                    this.stringBuffer.append(PADDING);
                }
            } else { //不需要填充，尾指针置于缓冲区末尾，防止越界
                this.end = length;
            }
        }
    }

    /**
     * 是否还有下一个切片
     *
     * @return
     */
    public boolean hasNext() {
        return (this.next != null);
    }

    /**
     * 返回下一个切片
     *
     * @return
     */
    public String next() {
        this.next = this.getSubString();
        return this.next;
    }

}
