package encryption.utils;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * 多线程工具类，任务注入机制
 */
public class TaskUtil {

    public static final long DEFAULT_TIME_OUT = 30L;
    public static final int TASK_ONCE_SIZE = 1500;

    private static ExecutorService executor;
    private static final int MAX_THREADS_QUANTITY = 10;
    private static final long MAX_TIME_OUT_SECOND_OF_TERMINATE = 10L;

    private TaskUtil() {

    }

    /**
     * 线程池的状态机：
     * running(处于工作状态，所有空闲线程均可用)
     * ->shutdown(处于关闭状态，不接受新任务，终止所有空闲线程，需要在超时时间内完成工作线程否则尝试终止它们)
     * ->terminated(处于终止状态，不接受任何新任务)
     * 由于执行器是非最终静态变量，需要确保它不会被反复生成新的线程池
     */

    public synchronized static void initExecutor() {
        if (isTerminated()) {
            executor = Executors.newFixedThreadPool(MAX_THREADS_QUANTITY);
        }
    }

    public synchronized static void invokeAll(List<Callable<Boolean>> callableList) {
        invokeAll(callableList, DEFAULT_TIME_OUT);
    }

    /**
     * 多任务
     */
    public synchronized static void invokeAll(List<Callable<Boolean>> callableList, long timeOutOfSeconds) {
        try {
            checkExecutor();
            executor.invokeAll(callableList, timeOutOfSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public synchronized static void initAndInvokeAll(List<Callable<Boolean>> callableList) {
        initAndInvokeAll(callableList, DEFAULT_TIME_OUT);
    }

    public synchronized static void initAndInvokeAll(List<Callable<Boolean>> callableList, long timeOutOfSeconds) {
        initExecutor();
        invokeAll(callableList, timeOutOfSeconds);
    }

    public synchronized static void recycleExecutor() {
        checkExecutor();
        executor.shutdown();
        try {
            //调用shutdown后不是马上关闭的，还要等待线程池所有线程终止
            executor.awaitTermination(MAX_TIME_OUT_SECOND_OF_TERMINATE, TimeUnit.SECONDS);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("线程池已终止：" + executor);
    }

    public static boolean isTerminated() {
        return executor == null || executor.isTerminated();
    }

    private static void checkExecutor() {
        if (executor == null) {
            throw new NullPointerException("executor is null !");
        }
        if (executor.isShutdown() || executor.isTerminated()) {
            throw new IllegalArgumentException("线程池非法状态：" + executor);
        }
    }
}
