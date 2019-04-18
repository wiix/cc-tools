package net.cccode.tools.algorithm;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.traverse.BreadthFirstIterator;
import org.junit.Test;

public class PathsOfSpecificDepthAlgorithmTest {

	@Test
	public void test() {
		String betContent;
		int specificDepth = 0;
		betContent = "201805314001/4001:3,1|201805314002/4002:3|201805314003/4003:1|201805314004/4004:1,0";//3 12
		specificDepth = 3;
		betContent = "201805303001/3001:3,1|201805303002/3002:3|201805303007/3007:1|201805303008/3008:1|201805303013/3013:1,0";//2
		specificDepth = 2;
		betContent = "201805314001/4001:1|201805314002/4002:1,0|201805314003/4003:1|201805314004/4004:3,1|201805314005/4005:3,1|201806314001/4001:1|201806314002/4002:1,0|201806314003/4003:1|201806314004/4004:3,1|201806314005/4005:3,1";//3  38
		specificDepth = 3;

		System.out.println("投递内容:" + betContent);
		Long timeStart = System.nanoTime();
		Graph<BetUnit, DefaultEdge> directedGraph = createGraph(betContent);
		Long timeSpend = System.nanoTime() - timeStart;
		System.out.println("创建树用时: " + (timeSpend / 1000000.0) + " ms");

		System.out.println("遍历顺序:");
		Set<BetUnit> vertexsSet = directedGraph.vertexSet();
		for (BetUnit currentVertex : vertexsSet) {
			System.out.println("起点:" + currentVertex);
			BreadthFirstIterator<BetUnit, DefaultEdge> depthFirstIterator = new BreadthFirstIterator<>(directedGraph, currentVertex);
			while (depthFirstIterator.hasNext()) {
				System.out.print(depthFirstIterator.next());
				if (depthFirstIterator.hasNext()) {
					System.out.print(" --> ");
				}
			}
			System.out.println();
			System.out.println();
		}
		//		Set<BetUnit> fixedVertexes = directedGraph.vertexSet().stream()
		//				.filter(unit -> unit.issue.equals("05314002/4002") | unit.issue.equals("05314003/4003"))
		//				.collect(Collectors.toSet());
		//	Set<String> fixedIssue = new HashSet<>(Arrays.asList(new String[] { "05314002/4002", "05314003/4003" }));
		//		Set<String> fixedIssue = new HashSet<>(
		//				Arrays.stream(new String[] { "05314002/4002", "05314003/4003" }).collect(Collectors.toList()));
		Set<String> fixedIssue = new HashSet<>(Arrays.asList("05314002/4002", "05314003/4003"));

		timeStart = System.nanoTime();
		//		PathsOfSpecificDepthAlgorithm<BetUnit, DefaultEdge> bellmanFordAlg = PathsOfSpecificDepthAlgorithm
		//				.defaultAlgorithm(directedGraph, specificDepth);
		PathsOfSpecificDepthAlgorithm<BetUnit, DefaultEdge> bellmanFordAlg = new PathsOfSpecificDepthAlgorithm<BetUnit, DefaultEdge>(
				directedGraph, specificDepth, true) {
			@Override
			public GraphPath<BetUnit, DefaultEdge> filterOut(GraphPath<BetUnit, DefaultEdge> sourcePath) {
				//				Set<String> pathIssue = new HashSet<String>();
				//				for (BetUnit unit : sourcePath.getVertexList()) {
				//					pathIssue.add(unit.issue);
				//				}
				if (fixedIssue == null || fixedIssue.isEmpty()) {
					return sourcePath;
				}
				Set<String> pathIssue = sourcePath.getVertexList().stream().map(unit -> unit.issue).collect(Collectors.toSet());
				return pathIssue.containsAll(fixedIssue) ? sourcePath : null;
			}
		};
		List<GraphPath<BetUnit, DefaultEdge>> slPaths = bellmanFordAlg.getPaths();
		timeSpend = System.nanoTime() - timeStart;

		////////////////////////////////////////////////////
		//		Long timeStart2 = System.nanoTime();
		//		List<GraphPath<BetUnit, DefaultEdge>> slPaths1 = slPaths.stream()
		//				.map(path -> path.getVertexList().stream().map(unit -> unit.issue).collect(Collectors.toSet())
		//						.containsAll(fixedIssue) ? path : null)
		//				.filter(result -> result != null).collect(Collectors.toList());
		//		Long timeSpend2 = System.nanoTime() - timeStart2;
		//		System.out.println("过滤结果1用时: " + (timeSpend2 / 1000000.0) + " ms");
		//		System.out.println(slPaths1.size());
		//		timeStart2 = System.nanoTime();
		//		List<GraphPath<BetUnit, DefaultEdge>> slPaths2 = filterOutJava7(slPaths, fixedIssue);
		//		timeSpend2 = System.nanoTime() - timeStart2;
		//		System.out.println("过滤结果2用时: " + (timeSpend2 / 1000000.0) + " ms");
		//		System.out.println(slPaths2.size());
		////////////////////////////////////////////////////

		System.out.println("节点数为 " + specificDepth + " 的组合:");
		for (GraphPath<BetUnit, DefaultEdge> path : slPaths) {

			System.out.println(path.getVertexList());
		}
		System.out.println("共计: " + slPaths.size());
		System.out.println("路径算法用时: " + (timeSpend / 1000000.0) + " ms");
	}


	public Graph<BetUnit, DefaultEdge> createGraph(String betContent) {
		Graph<BetUnit, DefaultEdge> directedGraph = new DefaultDirectedGraph<>(DefaultEdge.class);
		String[] issueArray = StringUtils.split(betContent, "|");
		int age = 0;
		for (String issueStr : issueArray) {
			String[] gameArray = StringUtils.split(issueStr, ":");
			String[] spfArray = StringUtils.split(gameArray[1], ",");
			String issue = gameArray[0];
			issue = issue.substring(4, issue.length());
			for (String spfStr : spfArray) {
				String id = issue + "." + spfStr;
				BetUnit bu = new BetUnit(id, age, issue);
				directedGraph.addVertex(bu);
				Collection<BetUnit> vertexsSet = directedGraph.vertexSet();
				for (BetUnit existsVertex : vertexsSet) {
					if (!existsVertex.equals(bu) && !existsVertex.issue.equals(bu.issue)) {
						directedGraph.addEdge(existsVertex, bu);
					}
				}
			}
			age++;
		}
		return directedGraph;
	}

	public class BetUnit {

		public BetUnit(String id, int age, String issue) {
			super();
			this.id = id;
			this.age = age;
			this.issue = issue;
		}

		public final String id;
		public final int age;
		public final String issue;


		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#equals(java.lang.Object)
		 */
		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (!(obj instanceof BetUnit)) {
				return false;
			}
			BetUnit bu = (BetUnit) obj;
			if (this.id == null || bu.id == null) {
				return false;
			}
			if (this.issue == null || bu.issue == null) {
				return false;
			}
			return this.id.equals(bu.id) && this.issue.equals(bu.issue) && this.age == bu.age;
		}


		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "id=[" + this.id + "], age=[" + this.age + "]";
		}

	}
}
