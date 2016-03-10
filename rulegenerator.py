#!/usr/bin/python

import sys
import MySQLdb
import numpy as np
import time
import math
import urllib
from igraph import * 
from suffix_tree import GeneralisedSuffixTree
from Levenshtein import *

def buildgraph(threshold, threshold_neighbors, start_data):
	cluster_graph = Graph()
	db = MySQLdb.connect(host="localhost", user="root", passwd="beetle", db="aggrhoney")

	print "[INFO] Building graph from existing data..."

	cur = db.cursor()
	cur.execute("SELECT * FROM request_log WHERE (query_string != '' OR request_body != '') LIMIT " + start_data)
	
	start_time = time.time()
	for row in cur.fetchall() :
		lastid = row[0]
		body = '' if row[7] is None else row[7].lower()
		query = '' if row[4] is None else row[4].lower()
		addrequest(cluster_graph, row[0], row[3].lower(), query, body,threshold)

	print "[INFO] Graph created..."

	while True:
		print "Generating IDS Rules..."
		elapsed_time = time.time() - start_time
		start_time = time.time()
		ftime.write(str(len(cluster_graph.vs)) + "," + str(elapsed_time * 1000) + ",")
		print "[INFO] " + str(len(cluster_graph.vs)) + " request are clustered in " + str(elapsed_time * 1000) + " ms..."
		tracegraph(cluster_graph, threshold_neighbors)
		elapsed_time = time.time() - start_time
		
		print "[INFO] Rules generated in " + str(elapsed_time * 1000) + " ms..."
		ftime.write(str(elapsed_time * 1000) + "\n")
		start_time = time.time()

		cur.execute("SELECT * FROM request_log WHERE (query_string != '' OR request_body != '') AND id > " + str(lastid) + " LIMIT 100")
		for row in cur.fetchall() :
			lastid = row[0]
			body = '' if row[7] is None else row[7].lower()
			query = '' if row[4] is None else row[4].lower()
			addrequest(cluster_graph, row[0], row[3].lower(), query, body,threshold)
		
		if cur.rowcount == 0:
			break
		#time.sleep(1)
		

def addrequest(cluster_graph, req_id, req_url, req_raw, post_body, threshold):
	tmp = threshold
	selected_ids = []
	substr_ids = []

	if sys.argv[4] == "unquote" or sys.argv[4] == "clean":
		req_raw = urllib.unquote(req_raw)
		if sys.argv[4] == "clean":
			if req_raw.startswith("id="):
				req_raw = req_raw[4:]
	#print req_raw
	
	if len(req_raw) < 10:
		return -1
	
	cluster_graph.add_vertex(name="id"+str(req_id), url=req_url, raw=req_raw, post_body=post_body, is_root=True, traced=False)
	new_vertex = cluster_graph.vs.find("id" + str(req_id))
	#print new_vertex["raw"]
	
	for vertex in cluster_graph.vs:
		if "id"+str(req_id) == vertex["name"]:
			continue
				
		tmplev = math.sqrt(distance(req_raw, vertex["raw"])**2+distance(post_body, vertex["post_body"])**2)
		
		if (req_raw in vertex["raw"] or vertex["raw"] in req_raw) and len(req_raw) > 0:
			substr_ids.append(vertex["name"])
			new_vertex["is_root"] = False
		elif tmplev < tmp:
			tmp = tmplev
			selected_ids = []
			selected_ids.append(vertex["name"])
			new_vertex["is_root"] = False
		elif tmplev == tmp:
			#print tmplev
			selected_ids.append(vertex["name"])
			new_vertex["is_root"] = False
	
	for i in selected_ids:
		#print cluster_graph.get_edgelist()
		cluster_graph.add_edge(source=i, target="id"+str(req_id), weight=tmp)
		
	for i in substr_ids:
		#print cluster_graph.get_edgelist()
		cluster_graph.add_edge(source=i, target="id"+str(req_id), weight=tmp)
		
	return 1

def tracegraph(cluster_graph, threshold_neighbors):
	cluster_graph = cluster_graph.spanning_tree()
	root_vertices = cluster_graph.vs.select(is_root=True)
	num_of_root = len(root_vertices)
	print "Root : ", num_of_root
	count = 0
	total = 0
	str_seq = []
	str_seq_post = []
	frules = open("coro.rules." + sys.argv[4] + "-inc", "w")

	for i in range(num_of_root):
		str_seq.append([])
		str_seq_post.append([])

	for root_vertex in root_vertices:
		if root_vertex["traced"] == False:
			num_of_vertices = 0
			str_seq[count].append(root_vertex["raw"])
			str_seq_post[count].append(root_vertex["post_body"])
			#print root_vertex["name"]
			root_vertex["traced"] = True
			num_of_vertices = 1 + tracevertex(root_vertex, str_seq[count], str_seq_post[count], num_of_vertices)
			
			post_rules = lcs(str_seq_post[count])
			get_rules = lcs(str_seq[count])
			
			if len(str_seq[count]) > 1 and len(get_rules) > 0 and num_of_vertices > threshold_neighbors:
				#print "Content of Root : " + root_vertex["raw"].strip() + "\n" + root_vertex["post_body"].strip()
				print "Vertices : " , num_of_vertices
				frules.write("alert tcp any any -> any 80 (content: \"" + lcs(str_seq[count]) + "\"; nocase; http_raw_uri;)\n")
			if len(str_seq_post[count]) > 1 and len(post_rules) > 0 and num_of_vertices > threshold_neighbors:
				#print "Vertices : " , num_of_vertices
				frules.write("alert tcp any any -> any 80 (content: \"" + lcs(str_seq_post[count]) + "\"; nocase; http_client_body;)\n")
			count = count + 1
			total = total + num_of_vertices
	
	for vertex in cluster_graph.vs:
		vertex["traced"] = False
	
	frules.close()
	print "Total Vertices : " , total

def tracevertex(vertex, str_seq, str_seq_post, num_of_vertices):
	neighbors = vertex.neighbors()
	count = 0
	#print vertex["raw"]
	
	for neighbor in neighbors:
		if neighbor["traced"] == False:
			str_seq.append(neighbor["raw"])
			str_seq_post.append(neighbor["post_body"])
			#print(neighbor["name"])
			neighbor["traced"] = True
			count = count + 1 + tracevertex(neighbor, str_seq, str_seq_post, num_of_vertices)
	
	#print "Count : " , len(neighbors)
	return num_of_vertices + count
	
def genrule(str_seq):
	stree = GeneralisedSuffixTree(str_seq)
	
	for shared in stree.sharedSubstrings(50):
		print '-'*70
	#	print shared
		for seq,start,stop in shared:
			if stop-start > 20:
				print seq, '['+str(start)+':'+str(stop)+']',
				print str_seq[seq][start:stop],
				print str_seq[:start]+'|'+ str_seq[seq][start:stop]+'|'+ str_seq[seq][stop:]
	print '='*70

def lcs(data):
	substr = ''
	if len(data) > 1 and len(data[0]) > 0:
		for i in range(len(data[0])):
			for j in range(len(data[0])-i+1):
				if j > len(substr) and all(data[0][i:i+j] in x for x in data):
					substr = data[0][i:i+j]
	return substr

try:
	ftime = open("time.log." + sys.argv[4] + "-inc", "w")
	buildgraph(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3])
except KeyboardInterrupt:
	print "Shutting down ...."
except IndexError:
	print "Usage : python cluster-agg.py <threshold_edge> <threshold_neighbors> <num_start_data> <raw|unquote|clean>"
