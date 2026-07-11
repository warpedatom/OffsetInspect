@{
    Severity = @('Error', 'Warning')
    ExcludeRules = @(
        # Human-readable terminal rendering is an intentional product feature.
        'PSAvoidUsingWriteHost',
        # Internal helper names prioritize domain clarity over noun singularization.
        'PSUseSingularNouns',
        # Constructor-heavy code is clearer with conventional positional .NET/cmdlet forms.
        'PSAvoidUsingPositionalParameters',
        # Private New-* helpers construct in-memory models rather than changing system state.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
