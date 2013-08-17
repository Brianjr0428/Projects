#!/usr/bin/env python

##########################
# wordgame.py
#
# An A* search to morph one word of
# length n into another word of length n,
# changing one letter at a time and using
# real words along the way.
#
# Invocation:  "wordgame.py word1 word2"
#
# Author: Kris Hauser (hauserk@indiana.edu) 8/22/2012
# Based on code by Mark Wilson (mw54@indiana.edu) 9/30/2011
###########################


"""This is the wordgame module.  It defines an search for the change-one-
letter-at-a-time game.  The goal of the game is to get from word A to word B,
changing only one letter at a time and creating a new (actual) word at every
step.  For instance, to change from "mare" to "colt":
-mare
-more
-mole
-molt
-colt

This module is an executable script.  To run the program and solve an
instance of the game, execute the following at the command line:
> wordgame.py startword goalword

On Windows, you may need to execute with the "python" command:
> python wordgame.py startword goalword"""

from collections import deque
from collections import Set
import heapq
import optparse

# Messages to be output to help the user
USAGE_MSG = \
"A script that solves a word-to-word morphing game by changing one letter\n"\
"at a time until the goal word is reached, taking steps only along real "\
"words.\n\n"\
"%prog [OPTIONS] WORD1 WORD2\n"
REVISITED_MSG = "Use BFS with revisited state detection."
ID_MSG = "Use iterative deepening search."
ASTAR_MSG = "Use A* search."

# A file containing a newline-delineated dictionary
DICT_FILENAME = 'words.txt'
# The letters of the alphabet
ALPHABET = [chr(i+97) for i in range(26)]
del i


#####################
#
# Returns a Python set object containing words of the given size,
# loaded from the file given by DICT_FILENAME.  Good for fast lookups
# of arbitrary strings to see if they're legal words.
#
def make_dictionary(size):
	"""Returns a Python set object containing words of the given size, loaded
	from the file whose name is given in the global variable DICT_FILENAME.
	This set object can be used for fast lookups of arbitrary strings to see
	if they're legal words (i.e., by using Python's "if VALUE in SET:"
	syntax)."""
	with open(DICT_FILENAME) as fin:
		words = fin.readlines()
	words = [w.strip().lower() for w in words if len(w.strip()) == size]
	return set(words)

class WordProblem:
        """ A definition of the state space and start/goal states for
        a word problem.  Also contains the dictionary of words of the correct
        length in the 'words' member."""

	def __init__(self,start,goal):
                self.start = start
                self.goal = goal
                self.words = make_dictionary(len(start))
                assert(self.goal in self.words)
                return

        def get_start(self):
                return self.start;

        def is_goal(self,state):
                return state == self.goal

	# IMPLEMENT ME!
	def successors(self, state):
		"""Return a list of valid successor states (i.e., actual words of the
                correct length) for the given state
		
		For example, if successor states were "mad" and "maw", this
		function returns:
		
		["mad", "maw"]
		"""
                valid_list = [];
                letter_diff = 0;
                # Check words to make sure each word to be inserted into valid_list has only letter different from given state
                for x in self.words:
                        for i in range(len(state)):
                                if x[i] != state[i]:
                                        letter_diff += 1;
                        if letter_diff == 1:
                                valid_list.append(x);
                        letter_diff = 0;
                                
                return valid_list;

def word_problem_heuristic(problem,state):
        # IMPLEMENT ME!
        letter_diff = 0

        # get the estimate of the cost by computing how many letter dfference between given node and the goal node  
        for i in range(len(state)):
                if problem.goal[i] != state[i]:
                        letter_diff += 1;
        return letter_diff;

class SearchNode:
        """A data structure containing a node in a search tree.  Maintains
        three members: state, parent, and depth.

        depth and parent are set automatically in the constructor
        if a parent is provided.  Otherwise, the parent pointer can be set
        using set_parent().
        """

                
        def __init__(self,state,parent=None):
                self.state = state
                self.set_parent(parent)
                self.g = 0
                self.h = 0
                self.f = 0
                return

        def set_parent(self,parent):
                self.parent = parent
                if parent != None:
                        self.depth = parent.depth+1
                else:
                        self.depth = 0

        def root(self):
                """Returns the root of this tree"""
                if self.parent == None: return self
                return self.parent.root()
                
        def path_from_root(self):
                """Returns a path of nodes from the root to this node"""
                if self.parent == None: return [self]
                return self.parent.path_from_root()+[self]


class SearchStats:
        """A data structure containing the statistics of a search.

        The search procedure is responsible for maintaining this structure
        for testing purposes. It should call:
        - on_generate() every time a new node is created in the search tree,
        - on_expand() every time the successor function is called, and
        - on_revisit() every time revisited state detection finds a revisited
          state.

        Incremental addding of two SearchStats structures is supported.
        So if a and b are two SearchStats, a += b will add all the counts
        from b into a.
        """
        def __init__(self):
                self.num_generated = 0
                self.num_expanded = 0
                self.num_revisited = 0
                return
                
        def on_generate(self):
                self.num_generated += 1
                return
                
        def on_expand(self):
                self.num_expanded += 1
                return
                
        def on_revisit(self):
                self.num_revisited += 1
                return

        def __iadd__(self,rhs):
                self.num_generated += rhs.num_generated
                self.num_expanded += rhs.num_expanded
                self.num_revisited += rhs.num_revisited
                return self

class SearchResult:
        """A data structure containing the result from a
        search.  An unsuccessful search result is given by
        SearchResult(False).  A successful result is given by
        SearchResult(True,node). """
        def __init__(self,successful,goal_node=None):
                self.successful = successful
                self.goal_node = goal_node
                return


def BFS(problem):
        """Performs a breadth first search for the given WordProblem 'problem'.

        Returns a (SearchResult,SearchStats) pair.
        """
        
        print "Starting BFS.."
        stats = SearchStats()

        #make the root of the search tree and test if it's a goal
        stats.on_generate()
        root = SearchNode(problem.start)
        if problem.is_goal(root.state):
                return (stats,SearchResult(True,root))
        
        #q implements the fifo fringe with a deque 
        q = deque([root])
        while len(q) > 0:
                #pick node from fringe
                n = q.popleft()
                #expand n
                stats.on_expand()
                for s in problem.successors(n.state):
                        #add successors as children of n
                        c = SearchNode(s,n)
                        stats.on_generate()
                        if problem.is_goal(s):
                                return (stats,SearchResult(True,c))
                        #add them to the fringe
                        q.append(c)

        #search failed
        return (stats,SearchResult(False))

def BFS_revisit(problem):
        """Performs a breadth first search for the given WordProblem 'problem'
        while remembering and properly treating visited states.
        
        Returns a (SearchResult,SearchStats) pair.  Do not forget to maintain
        your SearchStats data structure!  You will be graded on correctness.
        """

        print "Starting BFS with revisited state detection..."
        stats = SearchStats()
        
        
        #make the root of the search tree and test if it's a goal
        stats.on_generate()
        root = SearchNode(problem.start)
        if problem.is_goal(root.state):
                return (stats,SearchResult(True,root))
        
        #q implements the fifo fringe with a deque 
        q = deque([root])

        # make a set to store nodes that have been expanded
        visitList = set()
        while len(q) > 0:
                #pick node from fringe
                n = q.popleft()
                #expand n
                stats.on_expand()
                for s in problem.successors(n.state):
                        # check if the node has been visited
                        if s in visitList:
                                stats.on_revisit()
                        else:
                                visitList.add(s)        
                                #add successors as children of n
                                c = SearchNode(s,n)
                                stats.on_generate()
                                if problem.is_goal(s):
                                        return (stats,SearchResult(True,c))
                                #add them to the fringe
                                if c not in visitList:
                                        q.append(c)
                                
                                

        #search failed
        return (stats,SearchResult(False))

def depth_limited_DFS_callback(problem,limit,curnode):
        """A subroutine for depth_limited_DFS.  If the depth limit is hit, then 
        the SearchResult.successful member is set to the string 'cutoff'
        rather than True or False."""
        stats = SearchStats()

        #BONUS POINTS: Implement this so that infeasible queries do not
        #run forever
        
        if problem.is_goal(curnode.state):
                return (stats,SearchResult(True,curnode))

        #test for depth limit
        if curnode.depth == limit:
                return (stats,SearchResult('cutoff'))
        
        #expand to successors
        
        stats.on_expand()
        succ = problem.successors(curnode.state)
        for s in succ:
                stats.on_generate()
                c = SearchNode(s,curnode)
                (sstats,sres) = depth_limited_DFS_callback(problem,limit,c)
                stats += sstats

                #test for solution
                if sres.successful==True:
                        return (stats,sres)
                #test for cutoff
                if sres.successful=='cutoff':
                        cutoff = True
        
        #this branch failed
        if cutoff:
                return (stats,SearchResult('cutoff'))
        else:
                return (stats,SearchResult(False))

def depth_limited_DFS(problem,limit):
        """Performs an iterative-deepening search for the given WordProblem
        'problem'. If the depth limit is hit, then the SearchResult.successful
        member is set to the string 'cutoff' rather than True or False. """

        print "Starting depth-limited(%d) search..."%(limit,)
        (stats,res) = depth_limited_DFS_callback(problem,limit,SearchNode(problem.start))
        #mark the start node
        stats.on_generate()
        return (stats,res)

def iterative_deepening_search(problem):
        """Performs an iterative-deepening search for the given WordProblem
        'problem'. """

        print "Starting iterative deepening search..."
        stats = SearchStats()
        
        # IMPLEMENT ME
        depth = 0
        # do DFS from depth = 0
        while True:
                (stats,res) = depth_limited_DFS(problem, depth)
                if res.successful != 'cutoff':
                        return (stats,res)
                depth += 1
        #search failed
        return (stats,SearchResult(False))


def astar_search(problem):
        """Performs an A* search for the given WordProblem 'problem'
        while remembering and properly handling visited states.

        To implement the node data structures that you will need for this
        problem, we suggest making use of Python's ability to dynamically
        add properties to objects.  For example, you may want to set up the
        g, h, and f values of a node as follows:
          n = SearchNode(s,p)
          n.g = p.g+cost(p,n)
          n.h = heuristic_function(s)
          n.f = n.g+n.h

        You will also want to use Python's heapq module for implementing the
        priority queue.  Heaps are simply lists that allow popping off the
        lowest item and inserting items in logarithmic time.  You will likely
        use the heapq.heappop and heapq.heappush functions for this.
        """
        
        print "Starting A* search..."
        stats = SearchStats()
               
        # IMPLEMENT ME        
        #make the root of the search tree and test if it's a goal
        stats.on_generate()
        root = SearchNode(problem.start)

        #q implements the heapq fringe 

        root.g = 0
        root.h = word_problem_heuristic(problem, root.state)
        root.f = root.g + root.h
        to_visit = []
        visited = []
        heapq.heappush(to_visit, (root.f, root))
        
        while to_visit:
                #pop the lowest one
                n = heapq.heappop(to_visit)[1]
                if n.h ==0:
                        return (stats,SearchResult(True,n))
                
                visited.append(n)
                #expand n
                stats.on_expand()
                for s in problem.successors(n.state):
                        if s in visited:
                                continue
                        else:
                                visited.append(s)
                                c = SearchNode(s,n)
                                stats.on_generate()
                                c.g = n.g+1
                                c.h = word_problem_heuristic(problem, c.state)
                                if c.h == 0:
                                        return (stats,SearchResult(True,c))
                                c.f = c.g+c.h
                                if c not in visited:
                                        heapq.heappush(to_visit, (c.f, c))
                
        #search failed
        return (stats,SearchResult(False))

####################
#
# Runs a search for words given in the arguments to the program invocation
#
def run_game():
	"""Runs a change-a-letter search for start and goal words given in the
	command-line arguments.  Called automatically when this module is
	invoked as a program."""
	
	parser = optparse.OptionParser(usage=USAGE_MSG)
	parser.add_option('-r', metavar='BFSREVISIT', dest='bfs_revisit',
			  default=False, action='store_true',
                          help=REVISITED_MSG)
	parser.add_option('-i', metavar='ITERATIVEDEEPENING', dest='iterativedeepening',
                          default=False, action='store_true',
                          help=ID_MSG)
	parser.add_option('-a', metavar='ASTAR', dest='astar',
                          default=False, action='store_true',
                          help=ASTAR_MSG)
	opts,args = parser.parse_args()
	if len(args) < 2:
		parser.print_help()
		return
	startWord = args[0].lower()
	goalWord = args[1].lower()
	
	problem = WordProblem(startWord, goalWord)
	search_function = BFS
	if opts.bfs_revisit:
                search_function = BFS_revisit
        if opts.iterativedeepening:
                search_function = iterative_deepening_search
        if opts.astar:
                search_function = astar_search
	print "Starting search"
	(stats,res) = search_function(problem)
	print "Search result:",res.successful
	print "Generated:",stats.num_generated
	print "Expanded:",stats.num_expanded
	print "Revisited:",stats.num_revisited
	if res.successful:
                print "Path:"
                for node in res.goal_node.path_from_root():
                       	print "\t",node.state
        return
	

###################
#
# Handle invocation of this module
#		
if __name__ == "__main__":
	run_game()
