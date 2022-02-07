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

public class GraphASTMod2 extends GhidraScript {
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

    String insertNodes = "i v 779 x 3";
    String removeNodes = "i v 988 x 3,i v 286,i v 843,i v 266,i v 988 x 10,ram:2000ba54 o 101,ram:2000ba54 v 264,ram:2000ba54 o 102,ram:2000ba54 v 267,i v 272,i v 988 x 11,ram:2000ba56 o 103,ram:2000ba56 v 270,ram:2000ba56 o 104,ram:2000ba56 v 273,ram:2000ba5c o 109,i v 359,i v 845,ram:2000ba72 o 138,ram:2000ba5c o 293,ram:2000ba5c v 878,ram:2000ba72 o 295,ram:2000ba72 v 884";
    String updateNodes = "ram:2000ba3c v 1013,ram:2000b7de v 799,ram:2000ba3c v 1016,ram:2000b7de v 802,ram:2000ba3c v 1011,ram:2000b7de v 797,ram:2000ba78 v 847,ram:2000b804 v 674";

    


    String[] insertStringArray = insertNodes.split(","); 
    String[] removeStringArray = removeNodes.split(","); 
    String[] updateStringArray = updateNodes.split(","); 

    @Override
    public void run() throws Exception {
        PluginTool tool = state.getTool();
        if (tool == null) {
            println("Script is not running in GUI");
        }
        GraphDisplayBroker graphDisplayBroker = tool.getService(GraphDisplayBroker.class);
        if (graphDisplayBroker == null) {
            Msg.showError(this, tool.getToolFrame(), "GraphASTMod2 Error",
                    "No graph display providers found: Please add a graph display provider to your tool");
            return;
        }

        Address addr = this.currentAddress;
        func = this.getFunctionContaining(addr);
        if (func == null) {
            Msg.showWarn(this, state.getTool().getToolFrame(), "GraphASTMod2 Error",
                    "No Function at current location");
            return;
        }

        buildAST();

        GraphType graphType = new GraphTypeBuilder("AST")
                .vertexType(DEFAULT)
                .vertexType(CONSTANT)
                .vertexType(REGISTER)
                .vertexType(UNIQUE)
                .vertexType(PERSISTENT)
                .vertexType(REMOVED)
                .vertexType(INSERTED)
                .vertexType(MODIFIED)
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
                .defaultEdgeColor(WebColors.DARK_GRAY)
                .defaultVertexShape(VertexShape.ELLIPSE)
                .defaultLayoutAlgorithm("Hierarchical MinCross Coffman Graham")
                .useIcons(false)
                .arrowLength(15)
                .labelPosition(GraphLabelPosition.SOUTH)
                .shapeOverrideAttribute(SHAPE_ATTRIBUTE)
                .vertex(DEFAULT, VertexShape.ELLIPSE, WebColors.DARK_GRAY)
                .vertex(CONSTANT, VertexShape.ELLIPSE, WebColors.DARK_GREEN)
                .vertex(REGISTER, VertexShape.ELLIPSE, WebColors.NAVY)
                .vertex(UNIQUE, VertexShape.ELLIPSE, WebColors.BLACK)
                .vertex(PERSISTENT, VertexShape.ELLIPSE, WebColors.DARK_ORANGE)
                .vertex(REMOVED, VertexShape.ELLIPSE, WebColors.RED)
                .vertex(INSERTED, VertexShape.ELLIPSE, WebColors.MEDIUM_BLUE)
                .vertex(MODIFIED, VertexShape.ELLIPSE, WebColors.YELLOW_GREEN)
                .vertex(ADDRESS_TIED, VertexShape.ELLIPSE, WebColors.ORANGE)
                .vertex(OP, VertexShape.RECTANGLE, WebColors.DARK_GRAY)
                .edge(DEFAULT, WebColors.DARK_GRAY)
                .edge(WITHIN_BLOCK, WebColors.BLACK)
                .edge(BETWEEN_BLOCK, WebColors.RED)
                .build();

        graph = new AttributedGraph("AST Graph", graphType);
        buildGraph();
        JsonGraphExporter exporter = new JsonGraphExporter();
        List<String> lines = doExport(exporter, graph);
        String ast_json_string = String.valueOf(lines.get(0));
        println(ast_json_string);


        PrintWriter pw = new PrintWriter("/Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence/versions/ast_temp.json");
        pw.write(ast_json_string);
        pw.flush();
        pw.close();


        GraphDisplay graphDisplay = graphDisplayBroker.getDefaultGraphDisplay(false, monitor);

        String description = "AST Data Flow Graph For " + func.getName();
        graphDisplay.setGraph(graph, displayOptions, description, false, monitor);

        // Install a handler so the selection/location will map
        graphDisplay.setGraphDisplayListener(
                new ASTGraphDisplayListener(tool, graphDisplay, high, func.getProgram()));
    }

    private List<String> doExport(AttributedGraphExporter exporter, AttributedGraph graph2) throws IOException {
        File file = File.createTempFile("GraphTest", "." + exporter.getFileExtension());
        exporter.exportGraph(graph, file);
        List<String> lines = FileUtilities.getLines(file);
        return lines;
    }



    private Address getAddress(long offset){
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

    HashMap<String, Integer> inputs = new HashMap<>();

    protected AttributedVertex createVarnodeVertex(VarnodeAST vn) {
        String name = vn.getAddress().toString(true);
        String id = getVarnodeKey(vn);
        String vertexType = DEFAULT;
        if (vn.isRegister()) {
            Register reg = func.getProgram().getRegister(vn.getAddress(), vn.getSize());
            if (reg != null) {
                name = reg.getName();
            }
        }

        if (vn.isInput()) {
            println(id);
            Integer input_count = inputs.get(id);
            if (input_count == null) {
                inputs.put(id, 1);
            } else {
                println("second coming");
                Integer update = input_count + 1;
                inputs.put(id, update);
                println(update.toString());
                id = id + " x " + update.toString();
                println(id);
                
            }
        }

    if(ArrayUtils.contains(insertStringArray, id)){
        vertexType = INSERTED;
        println("\n\nhello");
    }    
    if(ArrayUtils.contains(removeStringArray, id)){
        vertexType = REMOVED;
    }
    if(ArrayUtils.contains(updateStringArray, id)){
        vertexType = MODIFIED;
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
            AddressSpace addrspace = func.getProgram().getAddressFactory().getAddressSpace((int) vn.getOffset());
            name += ' ' + addrspace.getName();
        } else if (opcode == PcodeOp.INDIRECT) {
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
        if(ArrayUtils.contains(insertStringArray, id)){
            vert.setVertexType(INSERTED);
        }    
        if(ArrayUtils.contains(removeStringArray, id)){
            vert.setVertexType(REMOVED);
        }        
        if(ArrayUtils.contains(updateStringArray, id)){
            vert.setVertexType(MODIFIED);
        }
       
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
        else {
         String shape = res.getAttribute(SHAPE_ATTRIBUTE);
         if (shape != null && shape.equals("Triangle Down")) {
             res = createVarnodeVertex(vn);
             vertices.put(vn.getUniqueId(), res);
         }
        }

        return res;
    }



    protected AttributedEdge createEdge(AttributedVertex in, AttributedVertex out, VarnodeAST vn) {
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
                    createEdge(v, o, vn);
                }
            }
            VarnodeAST outvn = (VarnodeAST) op.getOutput();
            if (outvn != null) {
                AttributedVertex outv = getVarnodeVertex(vertices, outvn);
                if (outv != null) {
                    createEdge(o, outv, outvn);
                }
            }
        }
    }

    protected Iterator<PcodeOpAST> getPcodeOpIterator() {
        Iterator<PcodeOpAST> opiter = high.getPcodeOps();
        return opiter;
    }

    class ASTGraphDisplayListener extends AddressBasedGraphDisplayListener {

        HighFunction highfunc;

        public ASTGraphDisplayListener(PluginTool tool, GraphDisplay display, HighFunction high,
                Program program) {
            super(tool, program, display);
            highfunc = high;
        }

        @Override
        protected Set<AttributedVertex> getVertices(AddressSetView selection) {
            return Collections.emptySet();
        }

        @Override
        protected AddressSet getAddresses(Set<AttributedVertex> vertices) {
            AddressSet set = new AddressSet();
            for (AttributedVertex vertex : vertices) {
                Address address = getAddress(vertex);
                if (address != null) {
                    set.add(address);
                }
            }
            return set;
        }

        @Override
        protected Address getAddress(AttributedVertex vertex) {
            if (vertex == null) {
                return null;
            }
            String vertexId = vertex.getId();
            int firstcolon = vertexId.indexOf(':');
            if (firstcolon == -1) {
                return null;
            }

            int firstSpace = vertexId.indexOf(' ');
            String addrString = vertexId.substring(0, firstSpace);
            return getAddress(addrString);
        }

        @Override
        public GraphDisplayListener cloneWith(GraphDisplay graphDisplay) {
            return new ASTGraphDisplayListener(tool, graphDisplay, highfunc, currentProgram);
        }
    }
}

