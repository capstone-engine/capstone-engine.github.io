// Test.java
import capstone.Capstone;

public class Test {
  public static byte [] CODE = { 0x55, 0x48, (byte) 0x8b, 0x05, (byte) 0xb8,
    0x13, 0x00, 0x00 };

  public static void main(String argv[]) {
    Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
    Capstone.CsInsn[] allInsn = cs.disasm(CODE, 0x1000);
    for (int i=0; i<allInsn.length; i++)
      System.out.printf("0x%x:\t%s\t%s\n", allInsn[i].address,
          allInsn[i].mnemonic, allInsn[i].opStr);
  }
}

