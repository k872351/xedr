// Rendering must terminate even when imported records contain invalid links.
export function graphParentChain(byId, startId) {
  const chain = []
  const seen = new Set()
  let node = byId[startId]
  while (node?.id != null && !seen.has(node.id)) {
    seen.add(node.id)
    chain.push(node)
    node = node.parent_id != null ? byId[node.parent_id] : null
  }
  return chain
}
