// Exports bounded, machine-readable facts without modifying the input program.
// @category VulnWeaver

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class ExportVulnWeaver extends GhidraScript {
    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 3) {
            throw new IllegalArgumentException("expected output path and two positive limits");
        }
        int functionLimit = Integer.parseInt(arguments[1]);
        int instructionLimit = Integer.parseInt(arguments[2]);
        if (functionLimit < 1 || instructionLimit < 1) {
            throw new IllegalArgumentException("analysis limits must be positive");
        }
        File target = new File(arguments[0]).getCanonicalFile();
        try (PrintWriter out = new PrintWriter(new FileWriter(target))) {
            out.print("{\"functions\":[");
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            boolean firstFunction = true;
            int functionCount = 0;
            while (functions.hasNext() && !monitor.isCancelled() && functionCount < functionLimit) {
                Function function = functions.next();
                if (!firstFunction) out.print(",");
                firstFunction = false;
                functionCount++;
                long size = function.getBody().getNumAddresses();
                out.printf(
                    "{\"name\":\"%s\",\"address\":%d,\"size\":%d,\"attributes\":{\"source\":\"ghidra\"}}",
                    escape(function.getName()), function.getEntryPoint().getOffset(), size
                );
            }
            out.print("],\"instructions\":[");
            InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
            boolean firstInstruction = true;
            int instructionCount = 0;
            while (instructions.hasNext() && !monitor.isCancelled() && instructionCount < instructionLimit) {
                Instruction instruction = instructions.next();
                if (!firstInstruction) out.print(",");
                firstInstruction = false;
                instructionCount++;
                StringBuilder bytes = new StringBuilder();
                for (byte value : instruction.getBytes()) {
                    bytes.append(String.format("%02x", value & 0xff));
                }
                Function function = currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
                String functionName = function == null ? "" : function.getName();
                out.printf(
                    "{\"address\":%d,\"bytes\":\"%s\",\"mnemonic\":\"%s\",\"operands\":\"%s\",\"function_name\":%s}",
                    instruction.getAddress().getOffset(), bytes.toString(),
                    escape(instruction.getMnemonicString()), escape(instruction.toString()),
                    function == null ? "null" : "\"" + escape(functionName) + "\""
                );
            }
            out.print("],\"imports\":[]}");
        }
    }
}
