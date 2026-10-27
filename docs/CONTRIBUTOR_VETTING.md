# Contributor Vetting: Check First, Form Later

This is the rule for anyone who says online that they want to contribute to BankShield HumanGate. No one gets an assignment, no one gets maintainer access, and no one gets the final contributor form before vetting is done and recorded.

Order matters, and it is fixed:

1. Person shows interest online.
2. Maintainer checks their GitHub profile properly.
3. Maintainer verifies activity, places, and types of contribution.
4. Maintainer verifies REA contribution separately, with links.
5. Only after vetting, maintainer sends the contributor form.
6. Maintainer provides that form later. Until then, no form is sent, and no form link is invented.

## Step 1: Identify the exact person

Record the exact GitHub username, not a display name, not a nickname, and not a similar username. One wrong letter is a different person. Record the profile link, the date of the check, and who checked it.

## Step 2: Check the profile properly

Check all of these, and save the evidence links, not just a verdict:

1. Profile exists, and is not empty, not a fresh shell account, and not a bot account.
2. Public repositories: how many, what languages, what topics, and when each was last updated.
3. Recent activity: commits, pull requests, issues, and reviews in the last 90 days, and in the last 12 months. Activity in only one burst, with long silence before and after, is noted as burst activity, not steady activity.
4. Where they contribute: their own repos only, or other people's repos, or organisations, or open source projects. Own repos only is weaker evidence than merged work in other people's repos.
5. What they contribute: code, tests, docs, security fixes, reviews, or only stars, forks, and comments. Stars and forks alone are not contributions. Comments alone are not code contributions.
6. Quality signals: merged pull requests, closed issues they fixed, tests added, and reviews that were accepted. Open pull requests that were never merged, or that were closed without merge, are noted as unmerged, not as merged work.
7. Red flags: copied repos with no original work, spam pull requests, template repos only, no commit history, private only claims with no public evidence, or a profile that does not match the claims they made in chat.

Use scripts/vet_contributor.py for a first pass on public data. The script is a helper, not a verdict. A human maintainer must read the actual pull requests and commits before approving anyone.

## Step 3: Verify REA contribution separately

REA here means Reverse Engineer Anything, official repo morluto/rea, website rea.tools, npm package rea-agents. A similar name, a fork with no merged work, or a mention of REA in a README is not a contribution to REA.

Verify REA contribution in this order, strongest first:

1. Merged pull request in morluto/rea, with link, title, date, and what changed.
2. Merged commit in morluto/rea, with link and author name matching the person.
3. Issue in morluto/rea that was closed as fixed, with link, and evidence that this person fixed it.
4. Review, docs, or test contribution in morluto/rea that was merged, with link.
5. No REA contribution found in public search. Record that as: No REA contribution found in public morluto/rea search on the check date. Do not record it as: Person has never contributed to REA anywhere, because private or deleted work cannot be proven from public search alone.

If the person claims an REA contribution, ask for the exact link. Check the link yourself. Do not accept a screenshot alone, because a screenshot can be edited or taken from another account.

Also check related REA ecosystem work separately, and label it as related, not as official REA work: awesome-rea lists, REA based tools, forks, and articles. Related work can be good evidence of interest and skill, but it is not the same as a contribution to morluto/rea.

## Step 4: Record the verdict

Use docs/CONTRIBUTOR_VETTING_CHECKLIST.md for each person, one file per person, with evidence links. Verdicts are only these four:

1. VERIFIED_ACTIVE: Real profile, steady recent public work, merged work in other repos, and evidence links saved.
2. VERIFIED_ACTIVE_NO_REA: Real profile and steady work, but no REA contribution found in public morluto/rea search.
3. ACTIVE_BUT_UNVERIFIED: Some activity, but evidence is weak, burst only, own repos only, or claims do not match public links. Do not send the form yet. Ask for exact links.
4. NOT_VERIFIED: Empty, fresh, bot like, spam, or mismatch. Do not send the form, and do not assign work.

REA status is recorded separately from the general verdict, as: REA_YES_MERGED, REA_YES_OTHER_MERGED_WORK, REA_RELATED_ONLY, or REA_NOT_FOUND.

## Step 5: Send the form, only after vetting, only when maintainer provides it

After a VERIFIED_ACTIVE or VERIFIED_ACTIVE_NO_REA verdict, the maintainer sends the contributor form. The form itself is not in this repo yet, because the maintainer, Rohan, said he will give it later. See docs/CONTRIBUTOR_FORM.md. Do not invent a form, do not invent a form link, and do not send a generic form in its place.

When Rohan gives the form, the maintainer adds the link to docs/CONTRIBUTOR_FORM.md, records the date it was sent to each vetted person, and only then sends it to that person, by the channel where they first showed interest, with their name and the vetting verdict in the internal record, not in a public post.

## Step 6: After the form

1. Person fills the form and returns it.
2. Maintainer reviews the form against the vetting record. If the form claims work that vetting did not find, ask for links again.
3. Maintainer assigns one small first task, with tests, from CONTRIBUTING.md. No finance related task, and no maintainer access, on a first contribution.
4. First pull request is reviewed under the normal pull request rules. Merged work, not interest alone, earns further tasks.

## What never happens

1. No form is sent before vetting.
2. No assignment is made on the basis of interest alone.
3. No private data from a profile, such as email, location, or employer, is copied into a public issue or public post. Vetting records with personal notes stay private to the maintainer, unless the person consents.
4. No contributor is announced publicly as verified until their first merged pull request is in, because vetting is an internal check, not a public endorsement.
