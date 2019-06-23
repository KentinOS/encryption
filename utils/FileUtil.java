package encryption.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class FileUtil implements Files {
    private final String fileName;

    private final static int BUFFER_SIZE = 8 * 1024;
    private final int bufferSize;

    private final static int MAX_FILE_SIZE = Integer.MAX_VALUE;

    public FileUtil(String fileName) {
        this.fileName = fileName;
        this.bufferSize = BUFFER_SIZE;
    }

    public FileUtil(String fileName, int bufferSize) {
        this.fileName = fileName;
        this.bufferSize = bufferSize;
    }

    @Override
    public StringBuffer read() {
        return read(this.fileName);
    }

    public static StringBuffer read(String fileName) {
        if (fileName == null) {
            throw new NullPointerException("fileName is null");
        }
        synchronized (FileUtil.class) {
            final File file = new File(fileName);
            return getReadBuffer(file);
        }
    }

    public static StringBuffer read(File file) {
        if (file == null) {
            throw new NullPointerException("file is null");
        }
        synchronized (FileUtil.class) {
            return getReadBuffer(file);
        }
    }

    private static StringBuffer getReadBuffer(File file) {
        final Long length = file.length();
        if (length > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("file's size too big");
        }
        final byte[] bytes = new byte[length.intValue()];
        try (
                FileInputStream fileInputStream = new FileInputStream(file)
        ) {
            return new StringBuffer(new String(bytes, 0, fileInputStream.read(bytes)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean write(StringBuffer stringBuffer) {
        return write(this.fileName, stringBuffer);
    }

    public static boolean write(String fileName, StringBuffer stringBuffer) {
        if (fileName == null) {
            throw new NullPointerException("fileName is null");
        }

        synchronized (FileUtil.class) {
            File file = new File(fileName);
            return getWriteBuffer(file, stringBuffer);

        }
    }

    public static boolean write(File file, StringBuffer stringBuffer) {
        if (file == null) {
            throw new NullPointerException("file is null");
        }

        synchronized (FileUtil.class) {
            return getWriteBuffer(file, stringBuffer);

        }
    }

    private static boolean getWriteBuffer(File file, StringBuffer stringBuffer) {
        final long length = file.length();
        if (length > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("file's size is too big");
        }
        try (
                FileOutputStream fileOutputStream = new FileOutputStream(file)
        ) {
            fileOutputStream.write(stringBuffer.toString().getBytes());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] s) {
        FileUtil.write("/home/cyh/www/tesFIle蔡", new StringBuffer("helloworld"));
        final StringBuffer buffer = FileUtil.read("/home/cyh/www/tesFIle蔡");
        System.out.print(buffer);
        System.out.println("sda");
    }

}
