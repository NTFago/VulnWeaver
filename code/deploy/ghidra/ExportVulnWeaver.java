// Exports bounded, machine-readable facts without modifying the input program.
// @category VulnWeaver

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;

public class ExportVulnWeaver extends GhidraScript {
    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private static String operands(Instruction instruction) {
        StringBuilder value = new StringBuilder();
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            if (index > 0) value.append(", ");
            value.append(instruction.getDefaultOperandRepresentation(index));
        }
        return value.toString();
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 5) {
            throw new IllegalArgumentException(
                "expected output path, function/instruction/pseudocode limits and text limit"
            );
        }
        int functionLimit = Integer.parseInt(arguments[1]);
        int instructionLimit = Integer.parseInt(arguments[2]);
        int pseudocodeLimit = Integer.parseInt(arguments[3]);
        int pseudocodeChars = Integer.parseInt(arguments[4]);
        if (Math.min(Math.min(functionLimit, instructionLimit),
                     Math.min(pseudocodeLimit, pseudocodeChars)) < 1) {
            throw new IllegalArgumentException("analysis limits must be positive");
        }

        File target = new File(arguments[0]).getCanonicalFile();
        // Ghidra maps the program at its own image base; downstream consumers key
        // facts by file virtual addresses (objdump/symbol table), so normalize.
        long imageBase = currentProgram.getImageBase().getOffset();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new FileWriter(target))) {
            // Emit the base as well: the address fields below are normalized by
            // it, but operand text still prints Ghidra's own addresses, so the
            // reader needs the base to bring branch targets into the same space.
            out.print("{\"image_base\":" + imageBase + ",\"functions\":[");
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
                    escape(function.getName()), function.getEntryPoint().getOffset() - imageBase, size
                );
            }

            out.print("],\"instructions\":[");
            InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
            boolean firstInstruction = true;
            int instructionCount = 0;
            StringBuilder xrefs = new StringBuilder();
            boolean firstXref = true;
            int xrefCount = 0;
            int xrefLimit = 4 * instructionLimit;
            while (instructions.hasNext() && !monitor.isCancelled()
                   && instructionCount < instructionLimit) {
                Instruction instruction = instructions.next();
                if (!firstInstruction) out.print(",");
                firstInstruction = false;
                instructionCount++;
                StringBuilder bytes = new StringBuilder();
                for (byte value : instruction.getBytes()) {
                    bytes.append(String.format("%02x", value & 0xff));
                }
                Function function = currentProgram.getFunctionManager()
                    .getFunctionContaining(instruction.getAddress());
                String functionName = function == null ? "" : function.getName();
                out.printf(
                    "{\"address\":%d,\"bytes\":\"%s\",\"mnemonic\":\"%s\",\"operands\":\"%s\",\"function_name\":%s}",
                    instruction.getAddress().getOffset() - imageBase, bytes.toString(),
                    escape(instruction.getMnemonicString()), escape(operands(instruction)),
                    function == null ? "null" : "\"" + escape(functionName) + "\""
                );
                // Resolved flow references.  Ghidra recovers indirect jumps
                // through jump tables, which operand text cannot express at all:
                // `jmp *%rax` prints no target, so without these the dispatcher
                // of a flattened function looks like it has no successors and
                // no dispatch structure can be measured.
                Reference[] references = instruction.getReferencesFrom();
                for (Reference reference : references) {
                    if (xrefCount >= xrefLimit) break;
                    RefType referenceType = reference.getReferenceType();
                    String kind;
                    if (referenceType.isCall()) kind = "call";
                    else if (referenceType.isJump()) kind = "jump";
                    else if (referenceType.isData()) kind = "data";
                    else continue;
                    // References into Ghidra's EXTERNAL space carry small
                    // offsets that would go negative once the image base is
                    // subtracted; they are not part of this image, so drop them
                    // rather than emit an address that cannot be normalized.
                    long targetOffset = reference.getToAddress().getOffset() - imageBase;
                    long sourceOffset = instruction.getAddress().getOffset() - imageBase;
                    if (sourceOffset < 0 || targetOffset < 0) continue;
                    Symbol targetSymbol = currentProgram.getSymbolTable()
                        .getPrimarySymbol(reference.getToAddress());
                    if (!firstXref) xrefs.append(",");
                    firstXref = false;
                    xrefCount++;
                    xrefs.append(String.format(
                        "{\"source_address\":%d,\"target_address\":%d,\"type\":\"%s\","
                        + "\"source_function\":%s,\"target_symbol\":%s}",
                        sourceOffset, targetOffset, kind,
                        function == null ? "null" : "\"" + escape(functionName) + "\"",
                        targetSymbol == null ? "null"
                            : "\"" + escape(targetSymbol.getName()) + "\""
                    ));
                }
            }

            out.print("],\"basic_blocks\":[],\"xrefs\":[" + xrefs + "],\"pseudocode\":[");
            functions = currentProgram.getFunctionManager().getFunctions(true);
            boolean firstPseudocode = true;
            int pseudocodeCount = 0;
            while (functions.hasNext() && !monitor.isCancelled()
                   && pseudocodeCount < pseudocodeLimit) {
                Function function = functions.next();
                DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
                DecompiledFunction decompiled = results.getDecompiledFunction();
                if (!results.decompileCompleted() || decompiled == null) continue;
                String body = decompiled.getC();
                if (body == null || body.isEmpty()) continue;
                if (body.length() > pseudocodeChars) body = body.substring(0, pseudocodeChars);
                if (!firstPseudocode) out.print(",");
                firstPseudocode = false;
                pseudocodeCount++;
                out.printf(
                    "{\"function_name\":\"%s\",\"address\":%d,\"text\":\"%s\",\"tool_name\":\"ghidra\"}",
                    escape(function.getName()), function.getEntryPoint().getOffset() - imageBase, escape(body)
                );
            }
            out.print("],\"imports\":[]}");
        }
        finally {
            decompiler.dispose();
        }
    }
}
