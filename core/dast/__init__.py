"""DAST: scanning web targets Bulwark does not control the source of (plan §22.4).

Everything SAST/SCA assumes -- "the thing being scanned is a workspace we were handed" -- is false
here: a web target is someone's live, internet-reachable site, and scanning it without permission is
not a scanning feature, it's an attack. `core.dast.ownership` is the gate every other piece of this
package sits behind: no campaign (`core.dast.campaign`) may run against a target whose ownership
hasn't been verified *at the moment the campaign starts*, not merely at some point in the past.
"""
