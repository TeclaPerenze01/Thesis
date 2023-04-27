package it.polimi.isgroup.secbpmn2bc.model.infer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.eclipse.emf.ecore.resource.Resource;

import it.polimi.isgroup.secbpmn2bc.model.BlockchainType;
import it.polimi.isgroup.secbpmn2bc.model.DataItems;
import it.polimi.isgroup.secbpmn2bc.model.Definitions;
import it.polimi.isgroup.secbpmn2bc.model.OnChainData;
import it.polimi.isgroup.secbpmn2bc.model.Process;
import it.polimi.isgroup.secbpmn2bc.model.SubProcess;
import it.polimi.isgroup.secbpmn2bc.model.Task;
import it.polimi.isgroup.secbpmn2bc.model.util.ModelNavigator;
import it.unitn.disi.sweng.gmt.model.GMTNode;
import it.unitn.disi.sweng.secbpmn.model.TaskType;

public class InferBCProperties {

	public boolean checkForErrors(List<ConsoleMessage> messages) {
		for (ConsoleMessage m : messages) {
			if (m.severity == Severity.ERROR) {
				return true;
			}
		}
		return false;
	}

	public boolean checkForWarnings(List<ConsoleMessage> messages) {
		for (ConsoleMessage m : messages) {
			if (m.severity == Severity.WARNING) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 
	 * Annotates the given Resource with admissible combinations and best
	 * assignments for each element.
	 * 
	 * @param resource the Resource to be annotated
	 * 
	 * @param override a Boolean indicating whether to override existing assignments
	 *                 or not
	 * 
	 * @return a list of ConsoleMessage objects containing information about the
	 *         annotation process
	 */
	public List<ConsoleMessage> annotate(Resource resource, Boolean override) {

		Definitions def = (Definitions) resource.getContents().get(0);

		// Admissible combinations
		HashMap<String, List<Combination>> result = new HashMap<String, List<Combination>>();

		// Find admissible combinations for the whole process (check for indirect
		// dependencies)
		System.out.println(1);
		List<ConsoleMessage> messages = determineAdmissibleCombinations(def, result, override);
		System.out.println(2);
		if (checkForErrors(messages)) {
		return messages;
		}
		System.out.println(3);
		// Find best assignment for each element
		propagateDown((GMTNode) def, result, true);
		System.out.println(4);
		setBCProperties(def, result);

		return messages;
	}
	
	/**
	 * 
	 * Check constraints for a given resource by determining admissible combinations
	 * and propagating them down the process hierarchy.
	 * @param resource The resource to check constraints for.
	 * 
	 * @return A list of ConsoleMessages indicating any warnings or errors found
	 *         during constraint checking.
	 */
	public List<ConsoleMessage> checkConstraint(Resource resource) {

		Definitions def = (Definitions) resource.getContents().get(0);

		// Admissible combinations
		HashMap<String, List<Combination>> result = new HashMap<String, List<Combination>>();

		// Find admissible combinations for the whole process (check for indirect
		// dependencies)
		List<ConsoleMessage> messages = determineAdmissibleCombinations(def, result, false);

		if (checkForErrors(messages)) {
			return messages;
		}
		System.out.println(1.1);
		propagateDown((GMTNode) def, result, false);

		System.out.println(result);

		List<GMTNode> nodes = ModelNavigator.getChildNodes(def);

		for (GMTNode node : nodes) {
			if (node instanceof Definitions) {
				if (((Definitions) node).getOnChainModel() == null) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(),
							"Property onChainModel has not been specified for element "));
					System.out.println("Property onChainModel has not been specified for element " + node.toString());
				}
				if (((Definitions) node).getBlockchainType() == BlockchainType.UNDEFINED) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(),
							"Property blockchainType has not been specified for element "));
					System.out.println("Property blockchainType has not been specified for element " + node.toString());
				}
			} else if (node instanceof Process) {
				if (((Process) node).getOnChainModel() == null) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(),
							"Property onChainModel has not been specified for element "));
					System.out.println("Property onChainModel has not been specified for element " + node.toString());
				}
			} else if (node instanceof SubProcess) {
				if (((SubProcess) node).getOnChainModel() == null) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(),
							"Property onChainModel has not been specified for element "));
					System.out.println("Property onChainModel has not been specified for element " + node.toString());
				}
			} else if (node instanceof DataItems) {
				if (((DataItems) node).getOnChainData() == OnChainData.UNDEFINED) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(),
							"Property onChainData has not been specified for element "));
					System.out.println("Property onChainData has not been specified for element " + node.toString());
				}
			} else if (node instanceof Task) {
				if (((Task) node).getOnChainExecution() == null) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(),
							"Property onChainExecution has not been specified for element "));
					System.out
							.println("Property onChainExecution has not been specified for element " + node.toString());
				}
			}

//			if (node instanceof Definitions || node instanceof Process || 
//					node instanceof SubProcess || node instanceof DataItems ||
//					node instanceof Task) {
//
//				List<Combination> list = result.get(node.getUuid());
//				
//				if (list == null || list.size() == 0) {
//					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "Empty set for element "));
//					System.out.println("Empty set for element " + node.toString());
//				} else if (list.size() > 1) {
//					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "One or more properties have not been specified for element "));
//					System.out.println("One or more properties for element " + node.toString() + " have not been specified");
//					
//					//TODO: ignorare duplicati o combinazioni non pertinenti per il nodo corrente
//				};
//			}
		}

		return messages;
	}

	/**
	 * Determine the admissible attribute combinations that satisfy all security
	 * constraints in the model
	 * 
	 * @param def      process definitions (root node in process tree)
	 * @param result
	 * @param sets     set of admissible attribute combinations for each element
	 *                 (element uuid, combinations)
	 * @param override if true, ignores previously assigned property values
	 * @return information regarding the execution of this function (e.g.,
	 *         conflicting properties)
	 */
	private List<ConsoleMessage> determineAdmissibleCombinations(Definitions def,
			HashMap<String, List<Combination>> result, Boolean override) {

		List<ConsoleMessage> messages = new ArrayList<ConsoleMessage>();

		List<GMTNode> nodes = ModelNavigator.getChildNodes(def);

		//System.out.println("b" + nodes.toString());

		// Find admissible combinations for each process element (independent from each
		// other)
		for (GMTNode node : nodes) {
		//	System.out.println("a" + node.toString());
			messages.addAll(inferElement(node, result));
		//	System.out.println("initial set of " + node.getUuid() + result);;
			
			
		}

	//	System.out.println("c" + messages.toString());

		// Check if something went wrong, e.g., conflicting properties hold for the same
		// element
		if (checkForErrors(messages)) {
			messages.add(new ConsoleMessage(Severity.ERROR, null, "Errors were found evaluating security annotations"));
			System.out.println("Errors were found evaluating security annotations");
			
			System.out.println("wrong set" + result);
			return messages;
		}

		messages.add(new ConsoleMessage(Severity.INFORMATION, null, "Finished evaluating security annotations"));
		System.out.println("Finished evaluating security annotations");
		System.out.println("right set" + result);

		propagateUp((GMTNode) def, result, messages, override);

		// Check if something went wrong, e.g., properties are incompatible with upper
		// elements in the process tree
		if (checkForErrors(messages)) {
			messages.add(
					new ConsoleMessage(Severity.ERROR, null, "Errors were found determining admissible properties"));
			System.out.println("Errors were found determining admissible properties");
			System.out.println(result);
			return messages;
		}

		messages.add(new ConsoleMessage(Severity.INFORMATION, null, "Finished determining admissible properties"));
		System.out.println("Finished determining admissible properties");
		System.out.println(result);

		return messages;
	}

	/**
	 * Infer admissible attribute combinations for each element subject to a
	 * security constraint
	 * 
	 * @param element security property
	 * @param result  set of admissible attribute combinations for each element
	 *                (element uuid, combinations)
	 * @return information regarding the execution of this function (e.g.,
	 *         conflicting properties)
	 */
	private List<ConsoleMessage> inferElement(GMTNode element, HashMap<String, List<Combination>> result) {
		List<ConsoleMessage> messages = new ArrayList<ConsoleMessage>();

		AuditabilityInference aui = new AuditabilityInference();
		AuthenticityInference ati = new AuthenticityInference();
		AvailabilityInference avi = new AvailabilityInference();
		BindOfDutyInference bdi = new BindOfDutyInference();
		FlowEnforceabilityInference fei = new FlowEnforceabilityInference();
		GatewayEnforceabilityInference gei = new GatewayEnforceabilityInference();
		IntegrityInference ii = new IntegrityInference();
		NonDelegationInference ndi = new NonDelegationInference();
		NonRepudiationInference nri = new NonRepudiationInference();
		PrivityInference pi = new PrivityInference();
		SeparationOfDutyInference sdi = new SeparationOfDutyInference();

		aui.infer(element, result, messages);
		ati.infer(element, result, messages);
		avi.infer(element, result, messages);
		bdi.infer(element, result, messages);
		fei.infer(element, result, messages);
		gei.infer(element, result, messages);
		ii.infer(element, result, messages);
		ndi.infer(element, result, messages);
		nri.infer(element, result, messages);
		pi.infer(element, result, messages);
		sdi.infer(element, result, messages);

		return messages;
	}

	private void setBCProperties(Definitions def, HashMap<String, List<Combination>> result) {

		List<GMTNode> nodes = ModelNavigator.getChildNodes(def);

		for (GMTNode node : nodes) {
			Combination c = null;
			List<Combination> list = result.get(node.getUuid());
			if (list != null) {
				if (list.size() > 0)
					c = list.get(0);
				else
					// empty set, so a conflict exists
					return;
			} else
				c = new Combination(null, null, 0);

			if (node instanceof Definitions) {
				if (c.blockchainType != null)
					((Definitions) node).setBlockchainType(c.blockchainType);
				else
					((Definitions) node).setBlockchainType(BlockchainType.PUBLIC);

				if (c.onChainModel != null)
					((Definitions) node).setOnChainModel(c.onChainModel);
				else
					((Definitions) node).setOnChainModel(true);

			} else if (node instanceof Process) {

				if (c.onChainModel != null)
					((Process) node).setOnChainModel(c.onChainModel);
				else
					((Process) node).setOnChainModel(true);

			} else if (node instanceof SubProcess) {

				if (c.onChainModel != null)
					((SubProcess) node).setOnChainModel(c.onChainModel);
				else
					((SubProcess) node).setOnChainModel(true);

			} else if (node instanceof DataItems) {

				if (c.onChainData != null)
					((DataItems) node).setOnChainData(c.onChainData);
				else
					((DataItems) node).setOnChainData(OnChainData.UNENCRYPTED);

			} else if (node instanceof Task) {

				if (c.onChainExecution != null)
					((Task) node).setOnChainExecution(c.onChainExecution);
				else if (((Task) node).getType() != TaskType.MANUAL && ((Task) node).getType() != TaskType.USER)
					((Task) node).setOnChainExecution(true);
				else
					((Task) node).setOnChainExecution(false);

			}
		}

	}

	/**
	 * Propagates up the security constraints from the children to the parent node.
	 * 
	 * @param node     the parent node to update with propagated constraints
	 * @param sets     the map of security constraint sets for each node uuid
	 * @param messages the list of console messages to append errors or warnings
	 * @param override whether to override the local constraints with the propagated
	 *                 ones
	 * @return the list of propagated combinations for the parent node
	 */
	private List<Combination> propagateUp(GMTNode node, HashMap<String, List<Combination>> sets,
			List<ConsoleMessage> messages, boolean override) {

		List<Combination> parentCombinations = null;
		List<Combination> localCombinations = sets.get(node.getUuid());
		List<List<Combination>> upCombinations = new ArrayList<>();
		List<Combination> finalCombinations = new ArrayList<>();
		System.out.println("PROPAGATEUP");
		if (!override) {
			localCombinations = constrain(localCombinations, node);
			
		}

		if (localCombinations != null) {
			System.out.println("Analyzing: " + node.getUuid());
			System.out.println("combinations after constraint with node: " + localCombinations);
			
			parentCombinations = new ArrayList<>();
			for (Combination c : localCombinations) {
				if (node instanceof Task || node instanceof DataItems) {
					parentCombinations
							.add(new Combination(c.blockchainType,c.onChainModel,
									c.enforcement, c.globalEnforcement));
				} else if (node instanceof Process || node instanceof SubProcess) {
					parentCombinations.add(new Combination(c.blockchainType,
							c.enforcement, c.globalEnforcement));
				} else if (!(node instanceof Definitions)) {
					parentCombinations.add(new Combination(c));
				}
			}
		}
		System.out.println("combinazioni no locali: " + parentCombinations);
		

		for (GMTNode child : node.getNodes()) {
			
			List<Combination> childConstraints = propagateUp(child, sets, messages, override);
			if (childConstraints != null && !childConstraints.isEmpty()) {
				System.out.println("TEMP");
				List<Combination> parentConstraints = new ArrayList<>();
				List<Combination> localConstraints = new ArrayList<Combination>();
				//compute constraints list
				for (Combination cc : childConstraints){
					if (node instanceof Process || node instanceof SubProcess){
						//local attribute is onChainModel
						localConstraints.add(new Combination(cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
						//parent attribute is blockchainType
						parentConstraints.add(new Combination(cc.blockchainType,cc.enforcement,cc.globalEnforcement));
					} else if (node instanceof Definitions) {
						//local attributes are blockchainType and onChainModel
						localConstraints.add(new Combination(cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement)); 
					} else if (node instanceof Task) {
						//local attribute is onChainExecution
						localConstraints.add(new Combination(cc.onChainExecution,cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
						//parent attributes are blockchainType and onChainModel
						parentConstraints.add(new Combination(cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
					} else if (node instanceof DataItems) {
						//local attribute is onChainData
						localConstraints.add(new Combination(cc.onChainData,cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
						//parent attributes are blockchainType and onChainModel
						parentConstraints.add(new Combination(cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
					} else {
						//all attributes must be propagated
						parentConstraints.add(new Combination(cc));
					}
				}
				
				//current node has some combinations
				if(localCombinations!=null){
					constrain(localCombinations,localConstraints);
					//a conflict exists among local constraints
					if(localCombinations.size()==0){
						System.out.println("Errors were found evaluating security annotations");
						messages.add(new ConsoleMessage(Severity.ERROR, node.getUuid(), "Conflicting privacy constraints hold for element "));
						//TODO decidere se terminare l'esecuzione della funzione.
					}
				}
					if(parentCombinations!=null){
						constrain(parentCombinations,parentConstraints);
					

					} else {
						parentCombinations = new ArrayList<Combination>();
						parentCombinations.addAll(parentConstraints);
						
					}
				}
			
		
			if(parentCombinations != null) {
				upCombinations.addAll(splitCombination(parentCombinations));
				System.out.println("upcombinations: " + upCombinations);
				}
			
			
			if (!upCombinations.isEmpty() && parentCombinations != null && !parentCombinations.isEmpty()) {
				finalCombinations = constrainSet(upCombinations, parentCombinations);
				System.out.println("PROPAGATEUP4");
			} else if (parentCombinations == null || parentCombinations.isEmpty()) {
				finalCombinations = constrainSetNode(upCombinations, null);
				System.out.println("PROPAGATEUP4");
			} else {
				System.out.println("Errors were found evaluating security annotations");
				messages.add(new ConsoleMessage(Severity.ERROR, node.getUuid(),
						"Conflicting privacy constraints hold for element "));
				// TODO: decide whether to terminate the function.
			}
			

		}
		
		
		sets.put(node.getUuid(), localCombinations);
		System.out.println("Analyzing: "+node.getUuid());
		System.out.println("Parent combinations: "+parentCombinations);
		System.out.println("Local combinations: "+sets.get(node.getUuid()));
		System.out.println("up sets:" + upCombinations);
		System.out.println("fianl combinations: " + finalCombinations);
		return finalCombinations;
	}
	
						
				

	public static List<List<Combination>> splitCombination(List<Combination> input) {
	    List<List<Combination>> output = new ArrayList<>();
	    for (Combination c : input) {
	        boolean found = false;
	        for (List<Combination> subset : output) {
	            if (!checkCombination(subset, c)) {
	                subset.add(c);
	                found = true;
	                break;
	            }
	        }
	        if (!found) {
	            List<Combination> newSubset = new ArrayList<>();
	            newSubset.add(c);
	            output.add(newSubset);
	        }
	    }

	    // Remove duplicates
	    List<List<Combination>> uniqueOutput = new ArrayList<>();
	    for (List<Combination> subset : output) {
	        if (!uniqueOutput.contains(subset)) {
	            uniqueOutput.add(subset);
	        }
	    }

	    return uniqueOutput;
	}

	private static boolean checkCombination(List<Combination> subset, Combination c) {
	    for (Combination s : subset) {
	        if (c.satisfies(s)) {
	            return true;
	        }
	    }
	    return false;
	}

	
	
	
	
	
	
	
	
	
	
	
	/**
	 * Filters a list of sets of combinations by checking whether each combination
	 * satisfies the parent constraints. If a combination satisfies a constraint,
	 * the constraint's global enforcement value is updated. Returns a list of
	 * combinations that satisfy at least one constraint.
	 *
	 * @param sets        the sets of combinations to filter
	 * @param constraints the constraints to check against
	 * @return a list of combinations that satisfy the constraint
	 */
	private List<Combination> constrainSet(List<List<Combination>> sets, List<Combination> constraints) {
		List<Combination> toAdd = new ArrayList<>();

		for (List<Combination> set : sets) {
			for (Combination combination : set) {
				boolean satisfiesConstraint = false;
				for (Combination constraint : constraints) {
					if (combination.satisfies(constraint)) {
						constraint.globalEnforcement = (constraint.globalEnforcement + combination.globalEnforcement)
								/ 2;
						satisfiesConstraint = true;
						break;
					}
				}
				if (satisfiesConstraint) {
					toAdd.add(combination);
				}
			}
		}

		return toAdd;
	}

	private List<Combination> constrainSetNode(List<List<Combination>> sets, GMTNode node) {
		List<Combination> result = new ArrayList<>();
		for (List<Combination> s : sets) {
			for (Combination c : s) {
				if (node instanceof Definitions)
					if ((((Definitions) node).getBlockchainType() == BlockchainType.UNDEFINED
							|| ((Definitions) node).getBlockchainType() == c.blockchainType)
							&& (((Definitions) node).getOnChainModel() == null
									|| ((Definitions) node).getOnChainModel() == c.onChainModel))
							
						result.add(c);
				if (node instanceof SubProcess)
					if (((SubProcess) node).getOnChainModel() == null
							|| ((SubProcess) node).getOnChainModel() == c.onChainModel)
						result.add(c);
				if (node instanceof Process)
					if (((Process) node).getOnChainModel() == null
							|| ((Process) node).getOnChainModel() == c.onChainModel)
						result.add(c);
				if (node instanceof DataItems)
					if (((DataItems) node).getOnChainData() == OnChainData.UNDEFINED
							|| ((DataItems) node).getOnChainData() == c.onChainData)
						result.add(c);
				if (node instanceof Task)
					if (((Task) node).getOnChainExecution() == null
							|| ((Task) node).getOnChainExecution() == c.onChainExecution)
						result.add(c);
			}
		}
		return result;
	}
	/**
	 * This function takes a GMTNode object and a HashMap containing a list of
	 * Combination objects for each node,propagates the combinations down to the child nodes. It analyzes the
	 * node, retrieves the parent combinations,compares them to the current combinations, finds the best combination (if
	 * specified), and updates the HashMap with the propagated combinations. If findBest is true, it also finds the best last
	 * combination for nodes without child.
	 * 
	 * @param node     The GMTNode to analyze and propagate combinations for
	 * @param sets     The HashMap containing lists of Combination objects for each node
	 * @param findBest A boolean value specifying whether to find the best combination or not
	 */
	private void propagateDown(GMTNode node, HashMap<String, List<Combination>> sets, Boolean findBest) {

		System.out.println();
		System.out.println("Analyzing: " + node.getUuid());

		List<Combination> nodeCombinations = sets.get(node.getUuid());
		List<Combination> parentCombinations;

		if (node.getParent() != null) {
			parentCombinations = new ArrayList<Combination>();

			System.out.println("Parent combinations: " + parentCombinations);

			for (Combination parentCombination : sets.get(node.getParent().getUuid())) {
				if (node instanceof Process || node instanceof SubProcess) {
					parentCombinations.add(new Combination(parentCombination.blockchainType,
							parentCombination.enforcement, parentCombination.globalEnforcement));
				} else {
					parentCombinations
							.add(new Combination(parentCombination.blockchainType, parentCombination.onChainModel,
									parentCombination.enforcement, parentCombination.globalEnforcement));
				}
			}

			System.out.println("Current combinations: " + sets.get(node.getUuid()));
			System.out.println("Local combinations: " + nodeCombinations);

			if (findBest) {
				Combination best = getBestCombination(nodeCombinations);

				if (node.getNodes().isEmpty()) {
					Combination best1 = getBestLastCombination(nodeCombinations);
					if (best1 != null)
						sets.put(node.getUuid(), new ArrayList<Combination>(Arrays.asList(best1)));

				}

				if (best != null)
					sets.put(node.getUuid(), new ArrayList<Combination>(Arrays.asList(best)));

				System.out.println("Best combination: " + sets.get(node.getUuid()));
			} else
				sets.put(node.getUuid(), nodeCombinations);

			for (GMTNode child : node.getNodes())
				propagateDown(child, sets, findBest);

		}
	}

	/**
	 * 
	 * This private method constrains the admissible combinations based on a GMT
	 * node and a list of combinations. If the list of combinations is null, it
	 * creates a list of admissible combinations for the given node. Otherwise, it
	 * filters the admissible combinations from the given list of combinations for
	 * the given node.
	 * 
	 * @param nodeCombinations The list of combinations to filter (null to create a
	 *                         new list).
	 * @param node             The GMT node to filter the combinations for.
	 * @return A list of admissible combinations for the given node based on the
	 *         given list of combinations.
	 */
	private List<Combination> constrain(List<Combination> nodeCombinations, GMTNode node) {
		List<Combination> result = new ArrayList<Combination>();
		if (nodeCombinations == null) {
			// Create combinations
			if (node instanceof Definitions) {
				if (((Definitions) node).getBlockchainType() != BlockchainType.UNDEFINED) {
					if (((Definitions) node).getOnChainModel() != null)
						result.add(new Combination(((Definitions) node).getBlockchainType(),
								((Definitions) node).getOnChainModel(), Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
					else {
						result.add(new Combination(((Definitions) node).getBlockchainType(), true, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(((Definitions) node).getBlockchainType(), false, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
					}
				} else {
					if (((Definitions) node).getOnChainModel() != null) {
						result.add(new Combination(BlockchainType.PUBLIC, ((Definitions) node).getOnChainModel(),
								Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(BlockchainType.PRIVATE, ((Definitions) node).getOnChainModel(),
								Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					} else {
						result.add(new Combination(BlockchainType.PUBLIC, true, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(BlockchainType.PUBLIC, false, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(BlockchainType.PRIVATE, true, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(BlockchainType.PRIVATE, false, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
					}
				}
			}
			if (node instanceof SubProcess)
				if (((SubProcess) node).getOnChainModel() != null) {
					result.add(new Combination(BlockchainType.PRIVATE, ((SubProcess) node).getOnChainModel(),
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(BlockchainType.PUBLIC, ((SubProcess) node).getOnChainModel(),
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				}
			if (node instanceof Process)
				if (((Process) node).getOnChainModel() != null) {
					result.add(new Combination(BlockchainType.PRIVATE, ((Process) node).getOnChainModel(),
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(BlockchainType.PUBLIC, ((Process) node).getOnChainModel(),
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				}
			if (node instanceof DataItems)
				if (((DataItems) node).getOnChainData() != OnChainData.UNDEFINED) {
					result.add(new Combination(((DataItems) node).getOnChainData(), BlockchainType.PRIVATE, true,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((DataItems) node).getOnChainData(), BlockchainType.PUBLIC, true,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((DataItems) node).getOnChainData(), BlockchainType.PRIVATE, false,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((DataItems) node).getOnChainData(), BlockchainType.PUBLIC, false,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				}
			if (node instanceof Task)
				if (((Task) node).getOnChainExecution() != null) {
					result.add(new Combination(((Task) node).getOnChainExecution(), BlockchainType.PRIVATE, true,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((Task) node).getOnChainExecution(), BlockchainType.PUBLIC, true,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((Task) node).getOnChainExecution(), BlockchainType.PRIVATE, false,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((Task) node).getOnChainExecution(), BlockchainType.PUBLIC, false,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				}
			if (result.size() == 0)
				return null;
		} else {
			// Constrain admissible combinations
			for (Combination c : nodeCombinations) {
				if (node instanceof Definitions)
					if ((((Definitions) node).getBlockchainType() == BlockchainType.UNDEFINED
							|| ((Definitions) node).getBlockchainType() == c.blockchainType)
							&& (((Definitions) node).getOnChainModel() == null
									|| ((Definitions) node).getOnChainModel() == c.onChainModel))
						result.add(c);
				if (node instanceof SubProcess)
					if (((SubProcess) node).getOnChainModel() == null
							|| ((SubProcess) node).getOnChainModel() == c.onChainModel)
						result.add(c);
				if (node instanceof Process)
					if (((Process) node).getOnChainModel() == null
							|| ((Process) node).getOnChainModel() == c.onChainModel)
						result.add(c);
				if (node instanceof DataItems)
					if (((DataItems) node).getOnChainData() == OnChainData.UNDEFINED
							|| ((DataItems) node).getOnChainData() == c.onChainData)
						result.add(c);
				if (node instanceof Task)
					if (((Task) node).getOnChainExecution() == null
							|| ((Task) node).getOnChainExecution() == c.onChainExecution)
						result.add(c);
			}
		}
		return result;
	}

	
	
	private Combination getBestCombination(List<Combination> nodeCombinations) {
		Combination best = null;
		for (Combination c : nodeCombinations) {
			best = c;
		}
		return best;
	}

	public Combination getBestLastCombination(List<Combination> nodeCombinations) {
		Combination c = getSubSet(nodeCombinations, Enforcement.NATIVE);
		if (c != null) {
			return c;
		}
		c = getSubSet(nodeCombinations, Enforcement.POSSIBLE);
		if (c != null) {
			return c;
		}
		c = getSubSet(nodeCombinations, Enforcement.NO_ENFORCEMENT);
		return c;
	}

	public Combination getSubSet(List<Combination> nodeCombinations, Enforcement enforcement) {
		Combination maxEnforcementCombination = null;
		for (Combination c : nodeCombinations) {
			if (c.enforcement == enforcement) {
				if (maxEnforcementCombination == null
						|| c.globalEnforcement > maxEnforcementCombination.globalEnforcement) {
					maxEnforcementCombination = c;
				}
			}
		}
		return maxEnforcementCombination;
	}

	private void constrain(List<Combination> list, List<Combination> constraints) {
		List<Combination> toRemove = new ArrayList<Combination>();
		for(Combination i : list){
			Boolean found = false;
			for(Combination c : constraints){
				if(i.satisfies(c)){
					i.globalEnforcement = (i.globalEnforcement + c.globalEnforcement)/2;
					found = true;
					break;
				}
			}
			if(!(found)){
				toRemove.add(i);
			}
		}
		for (Combination deleted: toRemove){
			list.remove(deleted);
		}
	}
	private List<Combination> factorize(List<Combination> combinations) {
		List<Combination> newSet = new ArrayList<Combination>();
		for (Combination oldC: combinations){
			boolean keep = true;
			//check if a compatible combination is already present in new set
			for (Combination newC: newSet){
				Combination moreStringent = oldC.compareTo(newC);
				if (moreStringent!=null){
					//replace current combination with more stringent one
					newC = moreStringent;
					keep=false;
				}
			}
			//combination not present yet, add it
			if(keep){
				newSet.add(oldC);
			}
		}
		return newSet;
	}

	/*
	 * private void constrain(List<Combination> list, List<Combination> constraints)
	 * { List<Combination> toRemove = new ArrayList<Combination>(); for (Combination
	 * i : list) { Boolean found = false; for (Combination c : constraints) { if
	 * (i.satisfies(c)) { found = true; break; } } if (!(found)) { toRemove.add(i);
	 * } } for (Combination deleted : toRemove) { list.remove(deleted); } }
	 * 
	  private List<Combination> factorize(List<Combination> combinations) {
	 * List<Combination> newSet = new ArrayList<Combination>(); for (Combination
	 * oldC : combinations) { boolean keep = true; // check if a compatible
	 * combination is already present in new set for (Combination newC : newSet) {
	 * Combination moreStringent = oldC.compareTo(newC); if (moreStringent != null)
	 * { // replace current combination with more stringent one newC =
	 * moreStringent; keep = false; } } // combination not present yet, add it if
	 * (keep) { newSet.add(oldC); } } return newSet; }
	 */
}