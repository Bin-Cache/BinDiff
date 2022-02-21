/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Decompile the function at the cursor, then build data-flow graph (AST)
//@category PCode

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.WebColors;
import java.io.*;
import utilities.util.FileUtilities;
import ghidra.graph.exporter.*;
import java.io.File;
import org.apache.commons.lang3.ArrayUtils;

public class GenerateFuncAST extends GhidraScript {
    private static final String SHAPE_ATTRIBUTE = "Shape";

    protected static final String DEFAULT = "Default";
    protected static final String CONSTANT = "Constant";
    protected static final String REGISTER = "Register";
    protected static final String UNIQUE = "Unique";
    protected static final String PERSISTENT = "Persistent";
    protected static final String ADDRESS_TIED = "Address Tied";
    protected static final String OP = "Op";

    protected static final String REMOVED = "REMOVED";
    protected static final String INSERTED = "INSERTED";
    protected static final String MODIFIED = "MODIFIED";

    protected static final String WITHIN_BLOCK = "Within Block";
    protected static final String BETWEEN_BLOCK = "Between Block";
    private Function func;
    private AttributedGraph graph;
    protected HighFunction high;

   
    String folder = "";
    String functionName = "";

   

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        functionName = args[0];
        folder = args[1];
        long offset = Long.decode(functionName);

        // Address addr = this.currentAddress;
        Address addr = getAddress(offset);
        func = this.getFunctionContaining(addr);
        if (func == null) {

            return;
        }

        buildAST();

		GraphType graphType = new GraphTypeBuilder("AST")
				.vertexType(DEFAULT)
				.vertexType(CONSTANT)
				.vertexType(REGISTER)
				.vertexType(UNIQUE)
				.vertexType(PERSISTENT)
				.vertexType(ADDRESS_TIED)
				.vertexType(OP)
				.edgeType(DEFAULT)
				.edgeType(WITHIN_BLOCK)
				.edgeType(BETWEEN_BLOCK)
				.build();

            GraphDisplayOptions displayOptions = new GraphDisplayOptionsBuilder(graphType)
				.vertexSelectionColor(WebColors.DEEP_PINK)
				.edgeSelectionColor(WebColors.DEEP_PINK)
				.defaultVertexColor(WebColors.RED)
				.defaultEdgeColor(WebColors.NAVY)
				.defaultVertexShape(VertexShape.ELLIPSE)
				.defaultLayoutAlgorithm("Hierarchical MinCross Coffman Graham")
				.useIcons(false)
				.arrowLength(15)
				.labelPosition(GraphLabelPosition.SOUTH)
				.shapeOverrideAttribute(SHAPE_ATTRIBUTE)
				.vertex(DEFAULT, VertexShape.ELLIPSE, WebColors.RED)
				.vertex(CONSTANT, VertexShape.ELLIPSE, WebColors.DARK_GREEN)
				.vertex(REGISTER, VertexShape.ELLIPSE, WebColors.NAVY)
				.vertex(UNIQUE, VertexShape.ELLIPSE, WebColors.BLACK)
				.vertex(PERSISTENT, VertexShape.ELLIPSE, WebColors.DARK_ORANGE)
				.vertex(ADDRESS_TIED, VertexShape.ELLIPSE, WebColors.ORANGE)
				.vertex(OP, VertexShape.RECTANGLE, WebColors.RED)
				.edge(DEFAULT, WebColors.BLUE)
				.edge(WITHIN_BLOCK, WebColors.BLACK)
				.edge(BETWEEN_BLOCK, WebColors.RED)
				.build();


        graph = new AttributedGraph("AST Graph", graphType);
        buildGraph();
        JsonGraphExporter exporter = new JsonGraphExporter();
        List<String> lines = doExport(exporter, graph);
        String ast_json_string = String.valueOf(lines.get(0));

        PrintWriter pw = new PrintWriter("/Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence/" + folder
                + "/" + functionName + ".json");
        pw.write(ast_json_string);
        pw.flush();
        pw.close();
    }

    private List<String> doExport(AttributedGraphExporter exporter, AttributedGraph graph2) throws IOException {
        File file = File.createTempFile("GraphTest", "." + exporter.getFileExtension());
        exporter.exportGraph(graph, file);
        List<String> lines = FileUtilities.getLines(file);
        return lines;
    }

    private Address getAddress(long offset) {
        return this.currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private void buildAST() throws DecompileException {
        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);

        if (!ifc.openProgram(this.currentProgram)) {
            throw new DecompileException("Decompiler",
                    "Unable to initialize: " + ifc.getLastMessage());
        }
        ifc.setSimplificationStyle("normalize");
        DecompileResults res = ifc.decompileFunction(func, 30, null);
        high = res.getHighFunction();

    }

    private String getVarnodeKey(VarnodeAST vn) {
        PcodeOp op = vn.getDef();
        String id;
        if (op != null) {
            id = op.getSeqnum().getTarget().toString(true) + " v " +
                    Integer.toString(vn.getUniqueId());
        } else {
            id = "i v " + Integer.toString(vn.getUniqueId());
        }
        return id;
    }

    private String getOpKey(PcodeOpAST op) {
        SequenceNumber sq = op.getSeqnum();
        String id = sq.getTarget().toString(true) + " o " + Integer.toString(op.getSeqnum().getTime());
        return id;
    }

    // HashMap<String, Integer> inputs = new HashMap<>();

    protected AttributedVertex createVarnodeVertex(VarnodeAST vn) {
		String name = vn.getAddress().toString(true);
		String id = getVarnodeKey(vn);
		String vertexType = DEFAULT;
		if (vn.isConstant()) {
			vertexType = CONSTANT;
		}
		else if (vn.isRegister()) {
			vertexType = REGISTER;
			Register reg = func.getProgram().getRegister(vn.getAddress(), vn.getSize());
			if (reg != null) {
				name = reg.getName();
			}
		}
		else if (vn.isUnique()) {
			vertexType = UNIQUE;
		}
		else if (vn.isPersistent()) {
			vertexType = PERSISTENT;
		}
		else if (vn.isAddrTied()) {
			vertexType = ADDRESS_TIED;
		}
		AttributedVertex vert = graph.addVertex(id, name);
		vert.setVertexType(vertexType);

		// if it is an input override the shape to be a triangle
		if (vn.isInput()) {
			vert.setAttribute(SHAPE_ATTRIBUTE, VertexShape.TRIANGLE_DOWN.getName());
		}
		return vert;
	}

	protected AttributedVertex createOpVertex(PcodeOpAST op) {
		String name = op.getMnemonic();
		String id = getOpKey(op);
		int opcode = op.getOpcode();
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			Varnode vn = op.getInput(0);
			AddressSpace addrspace =
				func.getProgram().getAddressFactory().getAddressSpace((int) vn.getOffset());
			name += ' ' + addrspace.getName();
		}
		else if (opcode == PcodeOp.INDIRECT) {
			Varnode vn = op.getInput(1);
			if (vn != null) {
				PcodeOp indOp = high.getOpRef((int) vn.getOffset());
				if (indOp != null) {
					name += " (" + indOp.getMnemonic() + ')';
				}
			}
		}
		AttributedVertex vert = graph.addVertex(id, name);
		vert.setVertexType(OP);
		return vert;
	}

	protected AttributedVertex getVarnodeVertex(Map<Integer, AttributedVertex> vertices,
			VarnodeAST vn) {
		AttributedVertex res;
		res = vertices.get(vn.getUniqueId());
		if (res == null) {
			res = createVarnodeVertex(vn);
			vertices.put(vn.getUniqueId(), res);
		}
		return res;
	}

	protected AttributedEdge createEdge(AttributedVertex in, AttributedVertex out) {
		AttributedEdge newEdge = graph.addEdge(in, out);
		newEdge.setEdgeType(DEFAULT);
		return newEdge;
	}


    protected void buildGraph() {

        HashMap<Integer, AttributedVertex> vertices = new HashMap<>();

        Iterator<PcodeOpAST> opiter = getPcodeOpIterator();
        while (opiter.hasNext()) {
            PcodeOpAST op = opiter.next();
            AttributedVertex o = createOpVertex(op);
            for (int i = 0; i < op.getNumInputs(); ++i) {
                int opcode = op.getOpcode();
                if ((i == 0) && ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE))) {
                    continue;
                }
                if ((i == 1) && (opcode == PcodeOp.INDIRECT)) {
                    continue;
                }
                VarnodeAST vn = (VarnodeAST) op.getInput(i);
                if (vn != null) {
                    AttributedVertex v = getVarnodeVertex(vertices, vn);
                    createEdge(v, o);
                }
            }
            VarnodeAST outvn = (VarnodeAST) op.getOutput();
            if (outvn != null) {
                AttributedVertex outv = getVarnodeVertex(vertices, outvn);
                if (outv != null) {
                    createEdge(o, outv);
                }
            }
        }
    }

    protected Iterator<PcodeOpAST> getPcodeOpIterator() {
        Iterator<PcodeOpAST> opiter = high.getPcodeOps();
        return opiter;
    }

}
