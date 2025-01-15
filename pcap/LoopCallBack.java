import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.charset.Charset;
import java.util.List;

public class LoopCallBack {

  private static String LINE_SEPARATOR = System.getProperty(
      "line.separator");

  @FunctionalInterface
  public interface NativeCallback {
    void nativeCallback(MemorySegment user, MemorySegment header,
        MemorySegment packet);
  }

  class Handler {
    static void handle(MemorySegment user, MemorySegment header,
        MemorySegment packet) {
      System.out.print("Packet: ");
      System.out.println(
          packet.reinterpret(Integer.MAX_VALUE)
              .getString(54, Charset.defaultCharset()));
    }
  }

  public static void main(String[] args) throws Throwable {

////    SymbolLookup lib = linker.defaultLookup();
////    lib.find("C:\\Windows\\System32\\Npcap").orElseThrow();
//    SymbolLookup lib = SymbolLookup
//        .libraryLookup("C:\\Windows\\System32\\Npcap\\wpcap", Arena.ofAuto());

    Linker linker = Linker.nativeLinker();
    SymbolLookup libLookup = linker.defaultLookup();
    SymbolLookup lib = SymbolLookup.libraryLookup(
        "./hello.so",
        Arena.ofAuto());

    MethodHandle sayHello = linker.downcallHandle(
        lib.find("loop_handler").orElseThrow(),
        FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS));

    MethodHandle hdl = MethodHandles.lookup().findStatic(
        Handler.class,
        "handle",
        MethodType.methodType(
            void.class,
            MemorySegment.class,
            MemorySegment.class,
            MemorySegment.class));

    // Create a Java description of a C function implemented by a Java method
    FunctionDescriptor hdlDesc = FunctionDescriptor.ofVoid(
        ValueLayout.ADDRESS,
//        ValueLayout.ADDRESS.withTargetLayout(ValueLayout.JAVA_INT),
        ValueLayout.ADDRESS,
        ValueLayout.ADDRESS);

    // Create function pointer for qsortCompare
    MemorySegment hdlFunc = linker.upcallStub(
        hdl,
        hdlDesc,
        Arena.ofAuto());

    sayHello.invoke(hdlFunc);
  }
}
