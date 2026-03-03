
export default {
    fetch: async (_request: Request) => {
        return new Response(null, { status: 404 })
    }
} satisfies ExportedHandler
