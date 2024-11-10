package com.serverless

import com.amazonaws.services.lambda.runtime.Context
import com.amazonaws.services.lambda.runtime.RequestHandler
import com.serverless.Handler.TokenAuthorizerContext

class Handler : RequestHandler<TokenAuthorizerContext, Map<String, Any>> {

    private val validServiceKey = "tally"

    override fun handleRequest(
        input: TokenAuthorizerContext,
        context: Context
    ): Map<String, Any> {
        val effect = when (input.authorizationToken) {
            validServiceKey -> "Allow"
            else -> "Deny"
        }
        return generatePolicy(effect, input.methodArn.orEmpty(), principalId = "user")
    }

    private fun generatePolicy(
        effect: String,
        resource: String, principalId: String
    ) = mapOf(
        "principalId" to principalId,
        "policyDocument" to mapOf(
            "Version" to "2012-10-17",
            "Statement" to listOf(
                mapOf(
                    "Action" to "execute-api:Invoke",
                    "Effect" to effect,
                    "Resource" to resource
                )
            )
        )
    )

    data class TokenAuthorizerContext(
        val type: String? = null,
        val authorizationToken: String? = null,
        val methodArn: String? = null
    )
}
