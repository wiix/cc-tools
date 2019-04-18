package net.cccode.tools.algorithm;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Stack;
import java.util.stream.Collectors;

import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.Graphs;
import org.jgrapht.graph.GraphWalk;

/**
 * 
 * @author WiiX
 *
 * @param <V>
 * @param <E>
 */
public abstract class PathsOfSpecificDepthAlgorithm<V, E> {
	/**
	 * The underlying graph.
	 */
	protected final Graph<V, E> graph;
	// The specific length
	private final int specificDepth;

	private final boolean isDebug;


	public static <V, E> PathsOfSpecificDepthAlgorithm<V, E> defaultAlgorithm(Graph<V, E> graph, int specificDepth) {
		return new PathsOfSpecificDepthAlgorithm<V, E>(graph, specificDepth) {
			@Override
			public GraphPath<V, E> filterOut(GraphPath<V, E> sourcePath) {
				return sourcePath;
			}
		};
	}


	/**
	 * Constructs a new instance of the algorithm for a given graph
	 * 
	 * @param graph
	 * @param specificDepth
	 */
	public PathsOfSpecificDepthAlgorithm(Graph<V, E> graph, int specificDepth) {
		this(graph, specificDepth, false);
	}


	/**
	 * Constructs a new instance of the algorithm for a given graph
	 * 
	 * @param graph
	 * @param specificDepth
	 * @param isDebug
	 */
	public PathsOfSpecificDepthAlgorithm(Graph<V, E> graph, int specificDepth, boolean isDebug) {
		this.graph = Objects.requireNonNull(graph, "Graph is null");
		this.specificDepth = specificDepth;
		this.isDebug = isDebug;
	}


	/**
	 * 
	 * @return
	 */
	public List<GraphPath<V, E>> getPaths() {
		if (isDebug) {
			System.out.println("[graph] = " + graph);
			System.out.println("[specificDepth] = " + specificDepth);
		}
		List<GraphPath<V, E>> paths = new ArrayList<>();
		for (V startVertex : graph.vertexSet()) {
			if (isDebug) {
				System.out.println("[start] = " + startVertex);
			}
			LinkedList<Label> nodeLabels = runAlgorithm(startVertex);
			paths.addAll(buildPaths(startVertex, nodeLabels));
			if (isDebug) {
				System.out.println("[result] = " + nodeLabels);
				System.out.println();
				System.out.println();
			}
		}
		return paths;
	}


	private void printString(String str, long times) {
		for (long i = 0; i < times; i++) {
			System.out.print(str);
		}
	}


	private void printString(long times) {
		printString("    |", times);
	}


	/**
	 * Execute the main algorithm
	 */
	private LinkedList<Label> runAlgorithm(V startVertex) {
		//
		final LinkedList<Label> nodeLabels = new LinkedList<>();
		//final GenericFibonacciHeap<Label, Void> heap = new GenericFibonacciHeap<>(new LabelComparator());
		Stack<Label> stack = new Stack<>();
		//
		Label sourceLabel = new Label(startVertex, System.nanoTime(), 1, null, null);
		//
		//heap.insert(sourceLabel, null);
		stack.push(sourceLabel);
		//while (!heap.isEmpty()) {
		while (!stack.isEmpty()) {
			//Label curLabel = heap.removeMin().getKey();
			Label curLabel = stack.pop();
			long curDepth = curLabel.depth;
			V curVertex = curLabel.node;
			if (isDebug) {
				printString(curDepth);
				System.out.println("[pop] = " + curVertex);
				printString(curDepth);
				System.out.println("outgoing edges is: " + graph.outgoingEdgesOf(curVertex));
			}
			for (E e : graph.outgoingEdgesOf(curVertex)) {
				V u = Graphs.getOppositeVertex(graph, e, curVertex);
				Label newLabel = new Label(u, System.nanoTime(), curDepth + 1, curLabel, e);
				if (newLabel.depth >= this.specificDepth) {
					if (isDebug) {
						printString(curDepth);
						System.out.println("[add] = " + newLabel);
					}
					nodeLabels.add(newLabel);
				} else {
					stack.push(newLabel);
					if (isDebug) {
						printString(curDepth);
						System.out.println("[push] = " + newLabel);
					}
					//heap.insert(newLabel, null);
				}
			}
			//			if (isDebug) {
			//				System.out.println();
			//			}
		}
		return nodeLabels;
	}


	/**
	 * 
	 * @param source
	 * @param nodeLabels
	 * @return
	 */
	@SuppressWarnings("unused")
	private List<GraphPath<V, E>> buildPaths2(V source, LinkedList<Label> nodeLabels) {
		List<GraphPath<V, E>> paths = nodeLabels.stream().map(label -> {
			double weight = 0d;
			LinkedList<E> edgeList = new LinkedList<>();
			Label cur = label;
			while (cur != null && cur.fromPrevious != null) {
				weight += graph.getEdgeWeight(cur.fromPrevious);
				edgeList.push(cur.fromPrevious);
				cur = cur.previous;
			}
			return filterOut(new GraphWalk<>(graph, source, cur.node, edgeList, weight));
		}).filter(out -> out != null).collect(Collectors.toList());
		return paths;
	}


	private List<GraphPath<V, E>> buildPaths(V source, LinkedList<Label> nodeLabels) {
		List<GraphPath<V, E>> paths = new ArrayList<>();
		for (Label label : nodeLabels) {
			double weight = 0d;
			LinkedList<E> edgeList = new LinkedList<>();
			Label cur = label;
			while (cur != null && cur.fromPrevious != null) {
				weight += graph.getEdgeWeight(cur.fromPrevious);
				edgeList.push(cur.fromPrevious);
				cur = cur.previous;
			}
			GraphWalk<V, E> walk = new GraphWalk<>(graph, source, cur.node, edgeList, weight);
			if (filterOut(walk) != null) {
				paths.add(walk);
			} else {
				if (isDebug) {
					System.out.println("[ignore] = " + edgeList);
				}
			}
		}
		return paths;
	}


	public abstract GraphPath<V, E> filterOut(GraphPath<V, E> sourcePath);

	/**
	 * A node label.
	 */
	private class Label implements Comparable<Label> {
		public V node;
		public long value;
		public long depth;
		public Label previous;
		public E fromPrevious;


		public Label(V node, long value, long depth, Label previous, E fromPrevious) {
			this.node = node;
			this.value = value;
			this.depth = depth;
			this.previous = previous;
			this.fromPrevious = fromPrevious;
		}


		@Override
		public String toString() {
			return "Label [node=" + node + ", value=" + value + ", depth=" + depth + ", fromPrevious=" + fromPrevious + "]";
		}


		@Override
		public int compareTo(PathsOfSpecificDepthAlgorithm<V, E>.Label o) {
			if (this.value < o.value) {
				return -1;
			} else if (this.value > o.value) {
				return 1;
			}
			return 0;
		}
	}
}
