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

	public List<ConsoleMessage> annotate(Resource resource, Boolean override) {

		Definitions def = (Definitions) resource.getContents().get(0);

		// Admissible combinations
		HashMap<String, List<Combination>> result = new HashMap<String, List<Combination>>();

		// Find admissible combinations for the whole process (check for indirect
		// dependencies)
		List<ConsoleMessage> messages = determineAdmissibleCombinations(def, result, override);

		if (checkForErrors(messages)) {
			return messages;
		}

		// Find best assignment for each element
		propagateDown((GMTNode) def, result, true);

		setBCProperties(def, result);

		return messages;
	}

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

		System.out.println(nodes.toString());

		// Find admissible combinations for each process element (independent from each
		// other)
		for (GMTNode node : nodes) {
			System.out.println(node.toString());
			messages.addAll(inferElement(node, result));
		}

		System.out.println(messages.toString());

		// Check if something went wrong, e.g., conflicting properties hold for the same
		// element
		if (checkForErrors(messages)) {
			messages.add(new ConsoleMessage(Severity.ERROR, null, "Errors were found evaluating security annotations"));
			System.out.println("Errors were found evaluating security annotations");
			System.out.println(result);
			return messages;
		}

		messages.add(new ConsoleMessage(Severity.INFORMATION, null, "Finished evaluating security annotations"));
		System.out.println("Finished 1 evaluating security annotations");
		System.out.println(result);

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
		System.out.println("Finished  3 determining admissible properties");
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
	/*
	 * This function takes in four parameters: a GMTNode object, a HashMap object
	 * that maps a string to a List of Combination objects, a List of ConsoleMessage
	 * objects, and a Boolean variable "override". returns a List of Combination
	 * objects. If the "override" variable is false, it calls a function named
	 * "constrain" to constrain the localCombinations based on the current property
	 * assignments of the GMTNode object. Then, it checks if the localCombinations
	 * is not null and loops through each Combination object in localCombinations.
	 * Inside the loop, it checks the type of the GMTNode object and adds a new
	 * Combination object to the parentCombinations based on the type of the GMTNode
	 * object and the attributes of the current Combination object. Next, the
	 * function loops through each child GMTNode object of the current GMTNode
	 * object and recursively calls the "propagateUp" function on each child. If the
	 * "childConstraints" is not null loops through each Combination object in
	 * "childConstraints". Inside the loop, it checks the type of the GMTNode object
	 * and adds a new Combination object to the "tempConstraints" based on the type
	 * of the GMTNode object and the attributes of the current Combination object.
	 * Then, the function generates all possible subsets of the "tempConstraints"
	 * list and adds them to the "upCombinations" list. After that, the function
	 * constrains the "upCombinations" list based on the "parentCombinations" list
	 * and stores the result in the "finals" list. The final list correspond to the
	 * update combinations of the parent node.
	 **/

	private List<Combination> propagateUp(GMTNode node, HashMap<String, List<Combination>> sets,
			List<ConsoleMessage> messages, Boolean override) {
		List<List<Combination>> upCombinations = new ArrayList<>();
		List<Combination> localCombinations = sets.get(node.getUuid());
		List<Combination> finals = new ArrayList<>();

		if (!override) {
			// Constrain combinations based on current property assignments
			localCombinations = constrain(localCombinations, node);
		}

		if (localCombinations != null) {
			List<Combination> parentCombinations = new ArrayList<>();

			for (Combination c : localCombinations) {
				if (node instanceof Task || node instanceof DataItems) {
					// Select attributes not specific for a task or data item
					parentCombinations
							.add(new Combination(c.blockchainType, c.onChainModel, c.enforcement, c.globalenforcement));
				} else if (node instanceof Process || node instanceof SubProcess) {
					// Select attributes not specific for a process or subprocess
					parentCombinations.add(new Combination(c.blockchainType, c.enforcement, c.globalenforcement));
				} else if (!(node instanceof Definitions)) {
					// Select all attributes
					parentCombinations.add(new Combination(c));
				}
			}
			// constraint if the node is a parent
			for (GMTNode child : node.getNodes()) {
				List<Combination> childConstraints = propagateUp(child, sets, messages, override);

				if (childConstraints != null) {
					List<Combination> tempConstraints = new ArrayList<>();

					// Compute constraints list
					for (Combination cc : childConstraints) {
						if (node instanceof Process || node instanceof SubProcess) {
							tempConstraints
									.add(new Combination(cc.blockchainType, cc.enforcement, cc.globalenforcement));
						} else if (node instanceof Definitions) {
							// Local attributes are blockchainType and onChainModel
							tempConstraints.add(new Combination(cc.blockchainType, cc.onChainModel, cc.enforcement,
									cc.globalenforcement));
						} else if (node instanceof Task || node instanceof DataItems) {
							tempConstraints.add(new Combination(cc.blockchainType, cc.onChainModel, cc.enforcement,
									cc.globalenforcement));
						} else {
							// All attributes must be propagated
							tempConstraints.add(new Combination(cc));
						}
					}

					// Current node has some combinations
					if (!tempConstraints.isEmpty()) {
						List<List<Combination>> subsets = generateSubsets(tempConstraints);
						upCombinations.addAll(subsets);
					}

					// add to finals all the admissible combinations.
					if (!upCombinations.isEmpty()) {
						finals = constrainSet(upCombinations, parentCombinations);

						System.out.println("Analyzing: " + node.getUuid());
						System.out.println("Upward Propagation Combinations: " + upCombinations);
						System.out.println("Finals Propagation Combinations: " + finals);
					}
				}

			}
		}

		return finals;
	}

	/*
	 * The generateSubsets() function takes Stemp as input and returns a list of
	 * lists of combination. The generateSubsetsHelper() function is a recursive
	 * function that generates all possible subsets of the input list. The function
	 * starts by adding the current subset to the list of subsets. Then it loops
	 * through the input list, starting at the specified index, and adds each
	 * element to the current subset if it is not already in the subset. It then
	 * recursively calls itself with the updated current subset and the next index.
	 * Once all subsets have been generated, the function returns the list of subset
	 */

	public static List<List<Combination>> generateSubsets(List<Combination> inputList) {
		List<List<Combination>> subsets = new ArrayList<>();
		avoidRepetition(inputList, subsets, new ArrayList<>(), 0);
		return subsets;
	}

	private static void avoidRepetition(List<Combination> inputList, List<List<Combination>> subsets,
			List<Combination> currentSubset, int start) {
		subsets.add(new ArrayList<>(currentSubset));

		for (int i = start; i < inputList.size(); i++) {
			if (!currentSubset.contains(inputList.get(i))) {
				currentSubset.add(inputList.get(i));
				avoidRepetition(inputList, subsets, currentSubset, i + 1);
				currentSubset.remove(currentSubset.size() - 1);
			}
		}
	}

	/*
	 * The function iterates over each list of Combination objects in the
	 * constraints parameter, and for each Combination object in the constraintList,
	 * it checks whether it satisfies any of the Combination objects in the list
	 * parameter. If a Combination object in the list parameter satisfies the
	 * constraint, then the globalenforcement value of the constraint is updated. If
	 * a constraint is satisfied, it is added to the result list, and duplicates are
	 * removed using a HashSet.
	 */

	private List<Combination> constrainSet(List<List<Combination>> constraints, List<Combination> list) {
		List<Combination> result = new ArrayList<>();
		for (List<Combination> constraintList : constraints) {
			for (Combination c : constraintList) {
				boolean found = true;
				for (Combination i : list) {
					if (c.satisfies(i)) {
						c.globalenforcement = (c.globalenforcement + i.globalenforcement) / 2;
						found = true;
						break;
					}
				}
				if (found) {
					result.add(c);

				}
				if (!found) {
					break;
				}
			}
		}
		return new ArrayList<>(new HashSet<>(result));
	}

	/*
	 * unisce sup and s parents in s final e prende best combination da quest
	 * 
	 */

	private void propagateDown(GMTNode node, HashMap<String, List<Combination>> sets, Boolean findBest) {
		// parent vincolato, figlio vincolato -> calcola
		// parent libero, figlio vincolato -> non fare nulla
		// parent vincolato, figlio libero -> vincola figlio
		// parent libero, figlio libero -> non fare nulla

		List<Combination> nodeCombinations = sets.get(node.getUuid());
		List<Combination> parentCombinations;

		System.out.println();
		System.out.println("Analyzing: " + node.getUuid());

		if (node.getParent() != null) {
			parentCombinations = new ArrayList<Combination>();

			System.out.println("Parent combinations: " + parentCombinations);

			for (Combination parentCombination : sets.get(node.getParent().getUuid())) {
				if (node instanceof Process || node instanceof SubProcess) {
					parentCombinations.add(new Combination(parentCombination.blockchainType,
							parentCombination.enforcement, parentCombination.globalenforcement));
				} else {
					parentCombinations
							.add(new Combination(parentCombination.blockchainType, parentCombination.onChainModel,
									parentCombination.enforcement, parentCombination.globalenforcement));
				}
			}

			System.out.println("Current combinations: " + sets.get(node.getUuid()));
			System.out.println("Parent combinations: " + parentCombinations);

			if (findBest) {
				Combination best = getBestCombination(nodeCombinations);

				if (best != null)
					sets.put(node.getUuid(), new ArrayList<Combination>(Arrays.asList(best)));

				System.out.println("Best combination: " + sets.get(node.getUuid()));
			} else
				sets.put(node.getUuid(), nodeCombinations);

			for (GMTNode child : node.getNodes())
				propagateDown(child, sets, findBest);
		}
	}

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
		for(Combination c : nodeCombinations) {
			best = c;
		}
						
		return best;
	}
	 //devi creare metodo che se il nodo è figlio, la best combination deve essere tra tutte quelle presenti nel S temp quelle compatibili
	//con la best del genitore e una volta trovata, fare i constraint per selezionare quella del set di partenza
	
	

	/*private Combination getBestCombination(List<Combination> nodeCombinations) {
		Combination c = getSubSet(nodeCombinations, Enforcement.NATIVE);
		if (c != null)
			return c;
		c = getSubSet(nodeCombinations, Enforcement.POSSIBLE);
		if (c != null)
			return c;
		c = getSubSet(nodeCombinations, Enforcement.NO_ENFORCEMENT);
		return c;
	}

	private Combination getSubSet(List<Combination> nodeCombinations, Enforcement enforcement) {
		for (Combination c : nodeCombinations) {
			if (c.enforcement == enforcement)
				return c;
		}
		return null;
	}

	private void constrain(List<Combination> list, List<Combination> constraints) {
		List<Combination> toRemove = new ArrayList<Combination>();
		for (Combination i : list) {
			Boolean found = false;
			for (Combination c : constraints) {
				if (i.satisfies(c)) {
					found = true;
					break;
				}
			}
			if (!(found)) {
				toRemove.add(i);
			}
		}
		for (Combination deleted : toRemove) {
			list.remove(deleted);
		}
	}

	private List<Combination> factorize(List<Combination> combinations) {
		List<Combination> newSet = new ArrayList<Combination>();
		for (Combination oldC : combinations) {
			boolean keep = true;
			// check if a compatible combination is already present in new set
			for (Combination newC : newSet) {
				Combination moreStringent = oldC.compareTo(newC);
				if (moreStringent != null) {
					// replace current combination with more stringent one
					newC = moreStringent;
					keep = false;
				}
			}
			// combination not present yet, add it
			if (keep) {
				newSet.add(oldC);
			}
		}
		return newSet;
	}*/
}
