package helios.leave

# This is the policy an IAM engineer would keep in Git.
# The Leave Portal asks this question before a manager can approve:
#   Is this person a manager, of this same department, during business hours?
#
# Line by line:
#   default allow := false     start by saying no
#   input.subject.roles        who is clicking Approve
#   input.resource.department  whose leave it is
#   input.context.business_hours   weekday, 09:00 to 18:00 India time

default allow := false

allow if {
    input.action == "approve_leave"
    input.subject.roles[_] == "manager"
    input.subject.department == input.resource.department
    input.context.business_hours == true
}
